#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>

#include "reb/artifact.hpp"

namespace {

constexpr std::uint64_t kSessionId = 1;
constexpr std::uint64_t kNavigationId = 100;
constexpr std::uint64_t kFrameId = 200;

bool WriteArtifact(const std::uint64_t artifact_id,
                   const std::uint64_t parent_artifact_id,
                   const std::uint64_t creator_event_id,
                   const reb::ArtifactKind kind,
                   const std::string_view url,
                   const std::string_view mime_type,
                   const std::span<const std::byte> content) {
  reb::ArtifactHeader header;
  header.kind = kind;
  header.session_id = kSessionId;
  header.navigation_id = kNavigationId;
  header.frame_id = kFrameId;
  header.artifact_id = artifact_id;
  header.parent_artifact_id = parent_artifact_id;
  header.creator_event_id = creator_event_id;
  header.content_size = content.size();
  header.url_size = static_cast<std::uint32_t>(url.size());
  header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());

  std::cout.write(reinterpret_cast<const char*>(&header), sizeof(header));
  std::cout.write(url.data(), static_cast<std::streamsize>(url.size()));
  std::cout.write(mime_type.data(), static_cast<std::streamsize>(mime_type.size()));
  std::cout.write(reinterpret_cast<const char*>(content.data()),
                  static_cast<std::streamsize>(content.size()));
  return static_cast<bool>(std::cout);
}

}  // namespace

int main() {
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
  const auto javascript_bytes = std::as_bytes(std::span(kJavaScript.data(), kJavaScript.size()));
  if (!WriteArtifact(300, 0, 4, reb::ArtifactKind::kJavaScript,
                     "https://checkout.acme.test/assets/cart.js", "text/javascript",
                     javascript_bytes) ||
      !WriteArtifact(301, 300, 3, reb::ArtifactKind::kWasm,
                     "https://checkout.acme.test/assets/fingerprint.wasm", "application/wasm",
                     kWasmHeader)) {
    std::cerr << "Failed to write artifact transfer stream\n";
    return 1;
  }
  return 0;
}
