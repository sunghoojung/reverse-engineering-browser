#include <unistd.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

#include "reb/artifact.hpp"
#include "reb/local_ipc.hpp"

namespace {

constexpr std::uint64_t kSessionId = 1;
constexpr std::uint64_t kNavigationId = 100;
constexpr std::uint64_t kFrameId = 200;

struct Options final {
  std::string socket_path;
  std::string token_path;
  std::uint64_t session_id = kSessionId;
};

bool ParseSessionId(const std::string_view value, std::uint64_t& session_id) {
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), session_id);
  return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && session_id != 0;
}

bool ParseOptions(const int argc, char* argv[], Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--socket" && index + 1 < argc) {
      options.socket_path = argv[++index];
    } else if (argument == "--token-file" && index + 1 < argc) {
      options.token_path = argv[++index];
    } else if (argument == "--session-id" && index + 1 < argc) {
      if (!ParseSessionId(argv[++index], options.session_id)) {
        return false;
      }
    } else {
      return false;
    }
  }
  return options.socket_path.empty() == options.token_path.empty();
}

bool WriteBytes(const int descriptor, const std::span<const std::byte> bytes) {
  std::string error;
  if (!reb::WriteExact(descriptor, bytes, error)) {
    std::cerr << error << '\n';
    return false;
  }
  return true;
}

bool ReadAcceptedAck(const int descriptor, const std::uint64_t artifact_id) {
  reb::ArtifactAck ack;
  std::string error;
  if (!reb::ReadExact(descriptor, std::as_writable_bytes(std::span(&ack, 1)), error)) {
    std::cerr << "Unable to read artifact acknowledgment: " << error << '\n';
    return false;
  }
  const bool reserved_clear = std::ranges::all_of(
      ack.reserved1, [](const std::byte value) { return value == std::byte{0}; });
  if (ack.magic != reb::kArtifactAckMagic ||
      ack.protocol_version != reb::kArtifactProtocolVersion ||
      ack.ack_size != reb::kArtifactAckSize ||
      ack.status != reb::ArtifactReceiveStatus::kAccepted || ack.reserved0 != 0 ||
      ack.artifact_id != artifact_id || !reserved_clear) {
    std::cerr << "Artifact transfer was rejected or acknowledged incorrectly\n";
    return false;
  }
  return true;
}

bool WriteArtifact(const int descriptor,
                   const bool expect_ack,
                   const std::uint64_t session_id,
                   const std::uint64_t artifact_id,
                   const std::uint64_t parent_artifact_id,
                   const std::uint64_t creator_event_id,
                   const reb::ArtifactKind kind,
                   const std::string_view url,
                   const std::string_view mime_type,
                   const std::span<const std::byte> content) {
  reb::ArtifactHeader header;
  header.kind = kind;
  header.session_id = session_id;
  header.navigation_id = kNavigationId;
  header.frame_id = kFrameId;
  header.artifact_id = artifact_id;
  header.parent_artifact_id = parent_artifact_id;
  header.creator_event_id = creator_event_id;
  header.content_size = content.size();
  header.url_size = static_cast<std::uint32_t>(url.size());
  header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());

  return WriteBytes(descriptor, std::as_bytes(std::span(&header, 1))) &&
         WriteBytes(descriptor, std::as_bytes(std::span(url))) &&
         WriteBytes(descriptor, std::as_bytes(std::span(mime_type))) &&
         WriteBytes(descriptor, content) &&
         (!expect_ack || ReadAcceptedAck(descriptor, artifact_id));
}

}  // namespace

int main(const int argc, char* argv[]) {
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    std::cerr << "Usage: " << argv[0] << " [--socket PATH --token-file PATH --session-id ID]\n";
    return 2;
  }
  constexpr std::string_view kJavaScript = R"js(export function buildPayload(cart, fingerprint) {
  const payload = {
    cart,
    device: {
      locale: navigator.language,
      fingerprint,
    },
  };
  return JSON.stringify(payload);
}

export async function checkout(cart, fingerprint) {
  return fetch('/cart', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: buildPayload(cart, fingerprint),
  });
}
)js";
  constexpr std::array<std::byte, 8> kWasmHeader = {
      std::byte{0x00}, std::byte{0x61}, std::byte{0x73}, std::byte{0x6d},
      std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
  };
  constexpr std::string_view kJavaScriptVm = R"js(const guestProgram = Uint8Array.of(1, 7, 2, 3, 0);

export function runGuest(host, program = guestProgram) {
  let accumulator = 0;
  let pc = 0;
  while (pc < program.length) {
    switch (program[pc++]) {
      case 0: return accumulator;
      case 1: accumulator += program[pc++]; break;
      case 2: accumulator ^= program[pc++]; break;
      case 3: return host.canvasReadback(accumulator);
      default: throw new Error('unknown guest opcode');
    }
  }
  return accumulator;
}
)js";
  const auto javascript_bytes = std::as_bytes(std::span(kJavaScript.data(), kJavaScript.size()));
  const auto javascript_vm_bytes =
      std::as_bytes(std::span(kJavaScriptVm.data(), kJavaScriptVm.size()));
  std::string error;
  const int descriptor = options.socket_path.empty() ? STDOUT_FILENO
                                                     : reb::ConnectAuthenticatedLocalIpc(
                                                           options.socket_path, options.token_path,
                                                           options.session_id, error);
  if (descriptor < 0) {
    std::cerr << error << '\n';
    return 1;
  }
  const bool expect_ack = !options.socket_path.empty();
  const bool written =
      WriteArtifact(descriptor, expect_ack, options.session_id, 300, 0, 4,
                    reb::ArtifactKind::kJavaScript, "https://checkout.acme.test/assets/cart.js",
                    "text/javascript", javascript_bytes) &&
      WriteArtifact(descriptor, expect_ack, options.session_id, 301, 300, 3,
                    reb::ArtifactKind::kWasm, "https://checkout.acme.test/assets/fingerprint.wasm",
                    "application/wasm", kWasmHeader) &&
      WriteArtifact(
          descriptor, expect_ack, options.session_id, 302, 0, 0, reb::ArtifactKind::kJavaScript,
          "https://checkout.acme.test/assets/vm-sample.js", "text/javascript", javascript_vm_bytes);
  if (expect_ack && close(descriptor) != 0) {
    std::cerr << "Failed to close artifact socket\n";
    return 1;
  }
  if (!written) {
    std::cerr << "Failed to write artifact transfer stream\n";
    return 1;
  }
  return 0;
}
