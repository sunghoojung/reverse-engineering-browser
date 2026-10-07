#ifndef REB_EVIDENCE_GUARD_HPP_
#define REB_EVIDENCE_GUARD_HPP_

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <streambuf>
#include <string>
#include <string_view>
#include <type_traits>

namespace reb {

// Cooperative store ownership, not authentication or protection from another
// same-user program. The immutable guard must never be removed or replaced.
class EvidenceGuard final {
 public:
  EvidenceGuard() = default;
  ~EvidenceGuard() {
    if (descriptor_ >= 0) {
      static_cast<void>(flock(descriptor_, LOCK_UN));
      close(descriptor_);
    }
    if (directory_ >= 0) {
      close(directory_);
    }
  }
  EvidenceGuard(const EvidenceGuard&) = delete;
  EvidenceGuard& operator=(const EvidenceGuard&) = delete;

  [[nodiscard]] bool Acquire(const std::filesystem::path& root, const std::string& name) noexcept {
    if (descriptor_ >= 0 || name.empty() || name == "." || name == ".." ||
        name.find('/') != std::string::npos) {
      return false;
    }
    // An explicitly configured root may be a symlink; all entries below this
    // pinned directory, including the guard itself, must be direct entries.
    const int directory = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK);
    if (directory < 0) {
      return false;
    }
    struct stat root_stat {};
    if (fstat(directory, &root_stat) != 0 || !S_ISDIR(root_stat.st_mode) ||
        root_stat.st_uid != geteuid() || (root_stat.st_mode & 0022) != 0) {
      close(directory);
      return false;
    }
    int descriptor = openat(directory, name.c_str(),
                            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    const bool created = descriptor >= 0;
    if (descriptor < 0 && errno == EEXIST) {
      descriptor = openat(directory, name.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    }
    if (descriptor < 0) {
      close(directory);
      return false;
    }
    struct stat guard_stat {};
    bool valid = fstat(descriptor, &guard_stat) == 0 && S_ISREG(guard_stat.st_mode) &&
                 guard_stat.st_uid == geteuid() && guard_stat.st_nlink == 1 &&
                 (guard_stat.st_mode & 0777) == 0600 && flock(descriptor, LOCK_EX | LOCK_NB) == 0;
    if (valid && created) {
      valid = write(descriptor, kMarker.data(), kMarker.size()) ==
                  static_cast<ssize_t>(kMarker.size()) &&
              fsync(descriptor) == 0 && fsync(directory) == 0;
    }
    std::array<char, kMarker.size() + 1> marker{};
    if (valid) {
      valid = pread(descriptor, marker.data(), marker.size(), 0) ==
                  static_cast<ssize_t>(kMarker.size()) &&
              std::string_view(marker.data(), kMarker.size()) == kMarker;
    }
    struct stat entry {};
    if (valid) {
      valid = fstatat(directory, name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
              entry.st_dev == guard_stat.st_dev && entry.st_ino == guard_stat.st_ino &&
              S_ISREG(entry.st_mode) && entry.st_nlink == 1;
    }
    if (!valid) {
      close(directory);
      close(descriptor);
      return false;
    }
    descriptor_ = descriptor;
    directory_ = directory;
    return true;
  }

  [[nodiscard]] int Directory() const noexcept { return directory_; }
  [[nodiscard]] static bool SafeName(const std::string_view name) noexcept {
    return !name.empty() && name != "." && name != ".." && name.find('/') == std::string_view::npos;
  }
  [[nodiscard]] static bool SafeFile(const struct stat& metadata) noexcept {
    return S_ISREG(metadata.st_mode) && metadata.st_uid == geteuid() && metadata.st_nlink == 1 &&
           (metadata.st_mode & 0022) == 0;
  }
  // Do not pass O_TRUNC: validation must precede the first mutation. The caller
  // owns the returned descriptor and all I/O remains anchored to this inode.
  [[nodiscard]] static int OpenFile(const int directory,
                                    const std::string& name,
                                    const int flags) noexcept {
    if (!SafeName(name) || (flags & O_TRUNC) != 0) {
      return -1;
    }
    const int fd =
        openat(directory, name.c_str(), flags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0) {
      return -1;
    }
    struct stat metadata {};
    struct stat entry {};
    if (fstat(fd, &metadata) != 0 || !SafeFile(metadata) ||
        fstatat(directory, name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        metadata.st_dev != entry.st_dev || metadata.st_ino != entry.st_ino) {
      close(fd);
      return -1;
    }
    return fd;
  }

 private:
  static constexpr std::string_view kMarker = "REB_EVIDENCE_GUARD_V1\n";
  int descriptor_ = -1;
  int directory_ = -1;
};

// Cold-path buffered descriptor I/O. Unlike reopening a pathname with fstream,
// this retains the safe openat inode through its last flush and close.
class EvidenceFileBuffer final : public std::streambuf {
 public:
  EvidenceFileBuffer() = default;
  EvidenceFileBuffer(const EvidenceFileBuffer&) = delete;
  EvidenceFileBuffer& operator=(const EvidenceFileBuffer&) = delete;
  EvidenceFileBuffer(EvidenceFileBuffer&&) = delete;
  EvidenceFileBuffer& operator=(EvidenceFileBuffer&&) = delete;
  ~EvidenceFileBuffer() override { static_cast<void>(Close()); }
  [[nodiscard]] bool Open(const int descriptor, const bool writing) noexcept {
    if (descriptor_ >= 0 || descriptor < 0) {
      return false;
    }
    descriptor_ = descriptor;
    writing_ = writing;
    if (writing_) {
      setp(buffer_.data(), buffer_.data() + buffer_.size());
    }
    return true;
  }
  [[nodiscard]] bool Close() noexcept {
    if (descriptor_ < 0) {
      return true;
    }
    const bool flushed = sync() == 0;
    const bool closed = close(descriptor_) == 0;
    descriptor_ = -1;
    setp(nullptr, nullptr);
    setg(nullptr, nullptr, nullptr);
    return flushed && closed;
  }
  [[nodiscard]] int Descriptor() const noexcept { return descriptor_; }
  [[nodiscard]] bool Failed() const noexcept { return failed_; }

 protected:
  int sync() override {
    if (!writing_ || descriptor_ < 0) {
      return 0;
    }
    const char* begin = pbase();
    const char* const end = pptr();
    while (begin != end) {
      const ssize_t count = write(descriptor_, begin, static_cast<std::size_t>(end - begin));
      if (count < 0 && errno == EINTR) {
        continue;
      }
      if (count <= 0) {
        const auto remaining = static_cast<std::size_t>(end - begin);
        std::memmove(buffer_.data(), begin, remaining);
        setp(buffer_.data(), buffer_.data() + buffer_.size());
        pbump(static_cast<int>(remaining));
        failed_ = true;
        return -1;
      }
      begin += count;
    }
    setp(buffer_.data(), buffer_.data() + buffer_.size());
    return 0;
  }
  int_type overflow(const int_type character) override {
    if (!writing_ || descriptor_ < 0 || sync() != 0) {
      return traits_type::eof();
    }
    if (!traits_type::eq_int_type(character, traits_type::eof())) {
      *pptr() = traits_type::to_char_type(character);
      pbump(1);
    }
    return traits_type::not_eof(character);
  }
  int_type underflow() override {
    if (writing_ || descriptor_ < 0) {
      return traits_type::eof();
    }
    ssize_t count;
    do {
      count = read(descriptor_, buffer_.data(), buffer_.size());
    } while (count < 0 && errno == EINTR);
    if (count <= 0) {
      failed_ = count < 0;
      return traits_type::eof();
    }
    setg(buffer_.data(), buffer_.data(), buffer_.data() + count);
    return traits_type::to_int_type(*gptr());
  }

 private:
  std::array<char, 8192> buffer_{};
  int descriptor_ = -1;
  bool writing_ = false;
  bool failed_ = false;
};
// Descriptor ownership and streambuf pointers cannot be copied or transferred
// without rebuilding their invariant. Keep that restriction compile-checked.
static_assert(!std::is_copy_constructible_v<EvidenceFileBuffer>);
static_assert(!std::is_copy_assignable_v<EvidenceFileBuffer>);
static_assert(!std::is_move_constructible_v<EvidenceFileBuffer>);
static_assert(!std::is_move_assignable_v<EvidenceFileBuffer>);

class EvidenceFile final : public std::iostream {
 public:
  EvidenceFile() : std::iostream(nullptr) { rdbuf(&buffer_); }
  void Open(const int descriptor, const bool writing) {
    if (!buffer_.Open(descriptor, writing)) {
      setstate(std::ios::badbit);
    }
  }
  void close() {
    if (!buffer_.Close()) {
      setstate(std::ios::badbit);
    }
  }
  [[nodiscard]] int Descriptor() const noexcept { return buffer_.Descriptor(); }
  [[nodiscard]] bool Failed() const noexcept { return buffer_.Failed(); }

 private:
  EvidenceFileBuffer buffer_;
};

class EvidenceDirectory final {
 public:
  ~EvidenceDirectory() {
    if (descriptor_ >= 0) {
      close(descriptor_);
    }
  }
  EvidenceDirectory() = default;
  EvidenceDirectory(const EvidenceDirectory&) = delete;
  EvidenceDirectory& operator=(const EvidenceDirectory&) = delete;
  [[nodiscard]] bool Open(const int parent, const std::string& name) noexcept {
    if (descriptor_ >= 0 || !EvidenceGuard::SafeName(name)) {
      return false;
    }
    if (mkdirat(parent, name.c_str(), 0700) != 0 && errno != EEXIST) {
      return false;
    }
    const int fd =
        openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      return false;
    }
    struct stat metadata {};
    if (fstat(fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0022) != 0) {
      close(fd);
      return false;
    }
    descriptor_ = fd;
    return true;
  }
  [[nodiscard]] int Descriptor() const noexcept { return descriptor_; }

 private:
  int descriptor_ = -1;
};

}  // namespace reb

#endif  // REB_EVIDENCE_GUARD_HPP_
