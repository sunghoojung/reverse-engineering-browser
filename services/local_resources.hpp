#ifndef REB_SERVICES_LOCAL_RESOURCES_HPP_
#define REB_SERVICES_LOCAL_RESOURCES_HPP_

#include <unistd.h>

#include <string>
#include <utility>

namespace reb::services {

class ScopedDescriptor final {
 public:
  explicit ScopedDescriptor(const int descriptor = -1) : descriptor_(descriptor) {}
  ScopedDescriptor(const ScopedDescriptor&) = delete;
  ScopedDescriptor& operator=(const ScopedDescriptor&) = delete;
  ~ScopedDescriptor() {
    if (descriptor_ >= 0) {
      close(descriptor_);
    }
  }

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] bool is_valid() const noexcept { return descriptor_ >= 0; }

 private:
  int descriptor_;
};

class ScopedSocketPath final {
 public:
  explicit ScopedSocketPath(std::string path) : path_(std::move(path)) {}
  ScopedSocketPath(const ScopedSocketPath&) = delete;
  ScopedSocketPath& operator=(const ScopedSocketPath&) = delete;
  ~ScopedSocketPath() {
    if (!path_.empty()) {
      unlink(path_.c_str());
    }
  }

 private:
  std::string path_;
};

}  // namespace reb::services

#endif  // REB_SERVICES_LOCAL_RESOURCES_HPP_
