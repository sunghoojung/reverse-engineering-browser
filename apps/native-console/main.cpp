#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>

#include "components/reverse_engineering_browser/common/native_console_io.h"
#include "components/reverse_engineering_browser/common/native_console_protocol.h"
#include "components/reverse_engineering_browser/common/native_probe_ipc.h"

namespace {

class Descriptor final {
 public:
  explicit Descriptor(int value = -1) noexcept : value_(value) {}
  ~Descriptor() {
    if (value_ >= 0)
      close(value_);
  }
  Descriptor(const Descriptor&) = delete;
  Descriptor& operator=(const Descriptor&) = delete;
  int get() const noexcept { return value_; }

 private:
  int value_;
};

std::string Quote(std::string_view value) {
  std::string result = "\"";
  for (char character : value) {
    const auto c = static_cast<unsigned char>(character);
    switch (c) {
      case '\\':
        result += "\\\\";
        break;
      case '"':
        result += "\\\"";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        // Console strings can contain terminal escape sequences. Render other
        // controls as visible text, never as terminal commands.
        if (c < 32 || c == 127) {
          constexpr char hex[] = "0123456789abcdef";
          result += "\\\\x";
          result += hex[c >> 4];
          result += hex[c & 15];
        } else {
          result += static_cast<char>(c);
        }
    }
  }
  result += '"';
  return result;
}

int Error(std::string_view code,
          std::string_view message,
          std::string_view help,
          int exit_code = 1) {
  std::cout << "error:\n  code: " << code << "\n  message: " << Quote(message)
            << "\nhelp: " << Quote(help) << '\n';
  return exit_code;
}

bool Number(std::string_view text, std::uint64_t& value) {
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  return error == std::errc{} && end == text.data() + text.size() && value != 0;
}

bool PrivateDirectory(const std::string& socket) {
  const auto slash = socket.rfind('/');
  if (slash == std::string::npos || socket.empty() || socket.front() != '/')
    return false;
  struct stat status {};
  const std::string parent = socket.substr(0, slash);
  return lstat(parent.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
         status.st_uid == geteuid() && (status.st_mode & 0777) == 0700;
}

bool LoadToken(const std::string& path, reb::NativeProbeLocalIpcToken& token) {
  const Descriptor file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  struct stat status {};
  if (file.get() < 0 || fstat(file.get(), &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_uid != geteuid() || (status.st_mode & 0777) != 0600 || status.st_size != 65)
    return false;
  std::array<char, 65> encoded{};
  std::size_t offset = 0;
  while (offset < encoded.size()) {
    const auto count = read(file.get(), encoded.data() + offset, encoded.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    offset += static_cast<std::size_t>(count);
  }
  if (encoded.back() != '\n')
    return false;
  for (std::size_t i = 0; i < token.size(); ++i) {
    unsigned int byte = 0;
    const auto [end, error] =
        std::from_chars(encoded.data() + i * 2, encoded.data() + i * 2 + 2, byte, 16);
    if (error != std::errc{} || end != encoded.data() + i * 2 + 2 || byte > 255)
      return false;
    token[i] = static_cast<std::byte>(byte);
  }
  return true;
}

bool SameToken(const reb::NativeProbeLocalIpcToken& left,
               const reb::NativeProbeLocalIpcToken& right) noexcept {
  unsigned int difference = 0;
  for (std::size_t i = 0; i < left.size(); ++i)
    difference |= std::to_integer<unsigned int>(left[i] ^ right[i]);
  return difference == 0;
}

bool SameUser(int socket) {
#if defined(__APPLE__)
  uid_t user = 0;
  gid_t group = 0;
  return getpeereid(socket, &user, &group) == 0 && user == geteuid();
#else
  struct ucred credentials {};
  socklen_t size = sizeof(credentials);
  return getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0 &&
         credentials.uid == geteuid();
#endif
}

const char* StatusName(reb::NativeConsoleStatus status) {
  constexpr std::array names{"OK",        "MALFORMED", "STALE_TARGET", "FORBIDDEN",
                             "EXCEPTION", "TIMEOUT",   "DISCONNECTED"};
  return names[static_cast<std::size_t>(status)];
}
const char* TypeName(reb::NativeConsoleType type) {
  constexpr std::array names{"undefined", "null",     "boolean", "number",  "string", "bigint",
                             "symbol",    "function", "object",  "promise", "targets"};
  return names[static_cast<std::size_t>(type)];
}

class Console final {
 public:
  explicit Console(int socket) : socket_(socket) {}
  int ExitCode() const noexcept { return exit_code_; }
  bool Targets() {
    reb::NativeConsoleRequest request;
    request.request_id = next_request_++;
    if (!Exchange(request, {}))
      return false;
    if (response_.status != reb::NativeConsoleStatus::kOk ||
        response_.type != reb::NativeConsoleType::kTargets)
      return ReportError();
    selected_ = 0;
    target_count_ = response_.item_count;
    std::cout << "targets[" << target_count_ << "]{id,origin}:\n";
    for (std::size_t i = 0; i < target_count_; ++i) {
      std::memcpy(&targets_[i], payload_.data() + i * sizeof(reb::NativeConsoleTarget),
                  sizeof(reb::NativeConsoleTarget));
      const auto& target = targets_[i];
      if (target.id == 0 || target.origin_bytes > target.origin.size() || target.reserved != 0 ||
          (target.flags & ~reb::kNativeConsoleTruncated) != 0)
        return Fail("Malformed target listing");
      for (std::size_t j = 0; j < i; ++j)
        if (targets_[j].id == target.id)
          return Fail("Duplicate target ID");
      std::cout << "  " << target.id << ','
                << Quote(std::string_view(target.origin.data(), target.origin_bytes)) << '\n';
    }
    std::cout << "truncated: " << (response_.flags ? "true" : "false") << '\n';
    if (target_count_ == 0)
      std::cout << "state: no eligible HTTP or HTTPS frames\n";
    std::cout << "help: \"Use :use <id> to select a document; :targets refreshes and clears "
                 "selection\"\n";
    std::cout.flush();
    return true;
  }

  bool Select(std::string_view input) {
    std::uint64_t id = 0;
    if (!Number(input, id) || std::none_of(targets_.begin(), targets_.begin() + target_count_,
                                           [id](const auto& target) { return target.id == id; })) {
      exit_code_ = 2;
      Error("STALE_TARGET", "Select an ID from the current target listing",
            "Run :targets, then :use <id>", 2);
      return true;
    }
    selected_ = id;
    std::cout << "selected: " << selected_ << '\n';
    return true;
  }

  bool Evaluate(std::string_view expression) {
    if (selected_ == 0 || expression.empty() ||
        expression.size() > reb::kNativeConsoleSourceLimit) {
      exit_code_ = 2;
      Error("INVALID_INPUT", "Select a target and supply 1 to 8192 bytes of JavaScript",
            "Run :targets, then :use <id>", 2);
      return true;
    }
    reb::NativeConsoleRequest request;
    request.operation = reb::NativeConsoleOperation::kEvaluate;
    request.request_id = next_request_++;
    request.target_id = selected_;
    request.source_bytes = static_cast<std::uint32_t>(expression.size());
    if (!Exchange(request, expression))
      return false;
    if (response_.status != reb::NativeConsoleStatus::kOk)
      return ReportError();
    if (response_.type == reb::NativeConsoleType::kTargets)
      return Fail("Unexpected target listing");
    std::cout << "result:\n  type: " << TypeName(response_.type) << "\n  value: "
              << Quote(std::string_view(reinterpret_cast<const char*>(payload_.data()),
                                        response_.payload_bytes))
              << "\n  truncated: " << (response_.flags ? "true" : "false") << '\n';
    std::cout.flush();
    return true;
  }

 private:
  bool Exchange(const reb::NativeConsoleRequest& request, std::string_view source) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
    if (!reb::NativeConsoleWrite(socket_, reb::NativeConsoleBytes(request), deadline) ||
        !reb::NativeConsoleWrite(socket_, std::as_bytes(std::span(source.data(), source.size())),
                                 deadline) ||
        !reb::NativeConsoleRead(socket_, reb::NativeConsoleBytes(response_), deadline) ||
        !reb::IsNativeConsoleResponse(response_, request.request_id) ||
        !reb::NativeConsoleRead(socket_, std::span(payload_).first(response_.payload_bytes),
                                deadline)) {
      return Fail("Native console disconnected, timed out, or returned a malformed response");
    }
    return true;
  }
  bool ReportError() {
    exit_code_ = std::max(exit_code_, 1);
    Error(StatusName(response_.status),
          std::string_view(reinterpret_cast<const char*>(payload_.data()), response_.payload_bytes),
          response_.status == reb::NativeConsoleStatus::kStaleTarget
              ? "Run :targets, then :use <id>"
              : "Correct the expression or restart the disposable console session");
    std::cout.flush();
    return true;
  }
  bool Fail(std::string_view message) {
    Error("PROTOCOL_ERROR", message, "Restart with make native-console REB_BRAVE_BINARY=<binary>");
    return false;
  }
  const int socket_;
  int exit_code_ = 0;
  std::uint64_t next_request_ = 1;
  std::uint64_t selected_ = 0;
  std::uint32_t target_count_ = 0;
  std::array<reb::NativeConsoleTarget, reb::kNativeConsoleTargetLimit> targets_{};
  reb::NativeConsoleResponse response_;
  std::array<std::byte, reb::kNativeConsolePayloadLimit> payload_{};
};

void Help() {
  std::cout << "description: Native JavaScript console for a disposable custom Brave session\n"
            << "usage: reb-console --socket <path> --token-file <path> --session <id> [--repl | "
               "--bridge]\n"
            << "commands: :targets, :use <id>, :begin ... :end, :quit, or JavaScript\n"
            << "limits: 8192 source bytes, 8192 result bytes, 64 targets, 200 ms execution budget\n"
            << "help: \"Run make native-console REB_BRAVE_BINARY=<binary>; pass REB_CONSOLE_REPL=0 "
               "for scripted stdin\"\n";
}

int Bridge(int socket) {
  std::array<std::byte, reb::kNativeConsolePayloadLimit> buffer{};
  std::uint64_t previous = 0;
  for (;;) {
    reb::NativeConsoleRequest request;
    std::cin.read(reinterpret_cast<char*>(&request), sizeof(request));
    if (std::cin.gcount() == 0 && std::cin.eof())
      return 0;
    if (std::cin.gcount() != sizeof(request) || !reb::IsNativeConsoleRequest(request) ||
        request.request_id <= previous)
      return 1;
    previous = request.request_id;
    std::cin.read(reinterpret_cast<char*>(buffer.data()), request.source_bytes);
    if (std::cin.gcount() != request.source_bytes)
      return 1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    reb::NativeConsoleResponse response;
    if (!reb::NativeConsoleWrite(socket, reb::NativeConsoleBytes(request), deadline) ||
        !reb::NativeConsoleWrite(socket, std::span(buffer).first(request.source_bytes), deadline) ||
        !reb::NativeConsoleRead(socket, reb::NativeConsoleBytes(response), deadline) ||
        !reb::IsNativeConsoleResponse(response, request.request_id) ||
        !reb::NativeConsoleRead(socket, std::span(buffer).first(response.payload_bytes), deadline))
      return 1;
    std::cout.write(reinterpret_cast<const char*>(&response), sizeof(response));
    std::cout.write(reinterpret_cast<const char*>(buffer.data()), response.payload_bytes);
    std::cout.flush();
    if (!std::cout)
      return 1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_path;
  std::string token_path;
  std::uint64_t session = 0;
  bool interactive = false;
  bool bridge = false;
  for (int i = 1; i < argc; ++i) {
    const std::string_view argument = argv[i];
    if (argument == "--version" || argument == "-v" || argument == "-V") {
      std::cout << "1\n";
      return 0;
    }
    if (argument == "--help") {
      Help();
      return 0;
    }
    if (argument == "--repl") {
      interactive = true;
      continue;
    }
    if (argument == "--bridge") {
      bridge = true;
      continue;
    }
    if (argument != "--socket" && argument != "--token-file" && argument != "--session") {
      return Error(
          "USAGE", "Unknown argument",
          "Valid flags: --socket, --token-file, --session, --repl, --bridge, --help, --version", 2);
    }
    if (++i == argc)
      return Error("USAGE", "Missing flag value", "Run reb-console --help", 2);
    if (argument == "--socket")
      socket_path = argv[i];
    if (argument == "--token-file")
      token_path = argv[i];
    if (argument == "--session" && !Number(argv[i], session))
      return Error("USAGE", "Invalid session ID", "Use a nonzero unsigned session ID", 2);
  }
  if (argc == 1) {
    std::cout << "state: disconnected\n";
    Help();
    return 0;
  }
  if (bridge && interactive)
    return Error("USAGE", "--bridge and --repl cannot be combined", "Choose one console mode", 2);
  sockaddr_un address{};
  reb::NativeProbeLocalIpcToken token{};
  if (!session || !PrivateDirectory(socket_path) ||
      socket_path.size() >= sizeof(address.sun_path) || !LoadToken(token_path, token)) {
    return Error("CONFIGURATION",
                 "A private socket directory and mode-0600 token file are required",
                 "Run make native-console REB_BRAVE_BINARY=<binary>", 2);
  }
  const Descriptor listener(socket(AF_UNIX, SOCK_STREAM, 0));
  address.sun_family = AF_UNIX;
  std::copy(socket_path.begin(), socket_path.end(), address.sun_path);
  if (listener.get() < 0 || fcntl(listener.get(), F_SETFD, FD_CLOEXEC) < 0 ||
      bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
      chmod(socket_path.c_str(), 0600) != 0 || listen(listener.get(), 1) != 0) {
    return Error("LISTEN_FAILED",
                 "Cannot create the private socket; existing paths are never replaced",
                 "Restart with a new disposable session directory");
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  int accepted = -1;
  while (std::chrono::steady_clock::now() < deadline) {
    pollfd waiting{listener.get(), POLLIN, 0};
    const int ready = poll(&waiting, 1, 250);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready < 0)
      break;
    if (ready == 0)
      continue;
    accepted = accept(listener.get(), nullptr, nullptr);
    if (accepted < 0)
      continue;
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    if (setsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
      close(accepted);
      accepted = -1;
      continue;
    }
#endif
    reb::NativeProbeLocalIpcHello hello;
    if (fcntl(accepted, F_SETFD, FD_CLOEXEC) == 0 && SameUser(accepted) &&
        reb::NativeConsoleRead(
            accepted, reb::NativeConsoleBytes(hello),
            std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds(1))) &&
        hello.magic == reb::kNativeProbeLocalIpcMagic &&
        hello.version == reb::kNativeProbeLocalIpcVersion && hello.size == sizeof(hello) &&
        hello.session_id == session && SameToken(hello.token, token) &&
        std::all_of(hello.reserved.begin(), hello.reserved.end(),
                    [](std::byte byte) { return byte == std::byte{}; }))
      break;
    close(accepted);
    accepted = -1;
  }
  unlink(socket_path.c_str());
  const Descriptor connection(accepted);
  if (accepted < 0)
    return Error("CONNECTION_TIMEOUT", "The custom browser did not authenticate within 30 seconds",
                 "Rebuild Brave with this integration and run make native-console again");
  std::cerr
      << "Native console connected. Commands can change the disposable page. No CDP attachment.\n";
  if (bridge)
    return Bridge(accepted);
  Console console(accepted);
  if (!console.Targets())
    return 1;
  std::string line;
  std::string expression;
  bool multiline = false;
  bool too_large = false;
  int input_exit_code = 0;
  for (;;) {
    if (interactive) {
      std::cerr << (multiline ? "... " : "js> ");
      std::cerr.flush();
    }
    // Bound input before allocation. std::getline would retain an arbitrarily
    // large pasted line even if validation rejected it afterward.
    line.clear();
    bool overflow = false;
    char character = 0;
    bool read_any = false;
    while (std::cin.get(character)) {
      read_any = true;
      if (character == '\n')
        break;
      if (line.size() < reb::kNativeConsoleSourceLimit)
        line += character;
      else
        overflow = true;
    }
    if (!read_any)
      break;
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line == ":quit")
      break;
    if (multiline) {
      if (line == ":end") {
        multiline = false;
        if (too_large) {
          input_exit_code = 2;
          Error("SOURCE_LIMIT", "Multiline input exceeds 8192 bytes", "Submit a smaller expression",
                2);
        } else if (!console.Evaluate(expression))
          return 1;
        expression.clear();
        continue;
      }
      if (overflow || expression.size() + line.size() + 1 > reb::kNativeConsoleSourceLimit)
        too_large = true;
      if (!too_large) {
        expression += line;
        expression += '\n';
      }
      continue;
    }
    if (overflow) {
      input_exit_code = 2;
      Error("SOURCE_LIMIT", "Input exceeds 8192 bytes", "Submit a smaller expression", 2);
      continue;
    }
    if (line == ":begin") {
      multiline = true;
      too_large = false;
      expression.clear();
      continue;
    }
    if (line == ":targets") {
      if (!console.Targets())
        return 1;
      continue;
    }
    if (line.starts_with(":use ")) {
      console.Select(std::string_view(line).substr(5));
      continue;
    }
    if (line == ":help") {
      Help();
      continue;
    }
    if (line.empty())
      continue;
    if (line.front() == ':') {
      input_exit_code = 2;
      Error("USAGE", "Unknown console command",
            "Commands: :targets, :use <id>, :begin, :end, :quit, :help", 2);
      continue;
    }
    if (!console.Evaluate(line))
      return 1;
  }
  if (multiline)
    return Error("INCOMPLETE_INPUT", "Multiline input ended before :end",
                 "Close multiline input with :end", 2);
  return std::max(input_exit_code, console.ExitCode());
}
