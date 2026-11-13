// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Stand-in declarations of the pinned Chromium, Blink and Mojo types the
// pausing debugger overlay uses, so a host compiler can check the overlay's
// name lookup, overload resolution, conversions and const-correctness. Each
// signature here is copied from the header at the revisions in
// `browser/config/*.rev`; nothing here implements behaviour, and the harness
// compiles rather than runs the overlay's browser paths.
#ifndef REB_TOOLS_NATIVE_DEBUGGER_PAUSE_CHROMIUM_STUBS_H_
#define REB_TOOLS_NATIVE_DEBUGGER_PAUSE_CHROMIUM_STUBS_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#define COMPONENT_EXPORT(x)
#define BLINK_EXPORT
#define CONTENT_EXPORT
#define FROM_HERE ::base::Location()
#define HANDLE_EINTR(x) (x)
#define DCHECK(x) static_cast<void>(0)
#define DCHECK_CURRENTLY_ON(x) static_cast<void>(0)
#define BUILDFLAG(x) 0
#define IS_LINUX 0
#define IS_CHROMEOS 0
#define IS_ANDROID 0
#define IS_APPLE 1

// base/memory/scoped_refptr.h
template <typename T>
class scoped_refptr {
 public:
  scoped_refptr() = default;
  scoped_refptr(std::nullptr_t) {}            // NOLINT(runtime/explicit)
  scoped_refptr(T* value) : value_(value) {}  // NOLINT(runtime/explicit)
  scoped_refptr(const scoped_refptr&) = default;
  scoped_refptr& operator=(const scoped_refptr&) = default;
  scoped_refptr(scoped_refptr&&) noexcept = default;
  scoped_refptr& operator=(scoped_refptr&&) noexcept = default;
  template <typename U>
  scoped_refptr(const scoped_refptr<U>& other) : value_(other.get()) {}  // NOLINT
  T* get() const { return value_; }
  T* operator->() const { return value_; }
  T& operator*() const { return *value_; }
  explicit operator bool() const { return value_ != nullptr; }
  void reset() { value_ = nullptr; }

 private:
  T* value_ = nullptr;
};

namespace base {

class Location {};

// base/time/time.h
class TimeDelta {
 public:
  constexpr TimeDelta() = default;
  explicit constexpr TimeDelta(std::int64_t micros) : micros_(micros) {}
  constexpr std::int64_t InMilliseconds() const { return micros_ / 1000; }
  constexpr std::int64_t InMicroseconds() const { return micros_; }

 private:
  std::int64_t micros_ = 0;
};
template <typename T>
constexpr TimeDelta Milliseconds(T n) {
  return TimeDelta(static_cast<std::int64_t>(n) * 1000);
}
class TimeTicks {
 public:
  static TimeTicks Now() { return TimeTicks(); }
  constexpr TimeDelta since_origin() const { return TimeDelta(); }
  friend constexpr TimeDelta operator-(TimeTicks, TimeTicks) { return TimeDelta(); }
  friend constexpr TimeTicks operator+(TimeTicks, TimeDelta) { return TimeTicks(); }
  friend constexpr bool operator>(TimeTicks, TimeTicks) { return false; }
};

// base/memory/raw_ptr.h
template <typename T>
class raw_ptr {
 public:
  raw_ptr() = default;
  raw_ptr(T* value) : value_(value) {}  // NOLINT(runtime/explicit)
  raw_ptr& operator=(T* value) {
    value_ = value;
    return *this;
  }
  T* operator->() const { return value_; }
  T& operator*() const { return *value_; }
  operator T*() const { return value_; }  // NOLINT(runtime/explicit)
  explicit operator bool() const { return value_ != nullptr; }
  T* get() const { return value_; }

 private:
  T* value_ = nullptr;
};

// base/values.h
class DictValue;
class ListValue;
class Value;

class Value {
 public:
  Value() noexcept = default;
  Value(Value&&) noexcept = default;
  Value& operator=(Value&&) noexcept = default;
  Value(const Value&) = delete;
  Value& operator=(const Value&) = delete;
  explicit Value(bool value);
  explicit Value(int value);
  explicit Value(double value);
  explicit Value(std::string_view value);
  explicit Value(const char* value);
  explicit Value(std::string&& value) noexcept;
  explicit Value(DictValue&& value) noexcept;
  explicit Value(ListValue&& value) noexcept;
  template <typename T>
  explicit Value(const T*) = delete;
  std::optional<bool> GetIfBool() const;
  std::optional<int> GetIfInt() const;
  const std::string* GetIfString() const;
  const DictValue* GetIfDict() const;
  const ListValue* GetIfList() const;
  Value Clone() const;
};

class ListValue {
 public:
  ListValue() = default;
  ListValue(ListValue&&) noexcept = default;
  ListValue& operator=(ListValue&&) noexcept = default;
  ListValue(const ListValue&) = delete;
  ListValue& operator=(const ListValue&) = delete;
  std::size_t size() const;
  bool empty() const;
  const Value* begin() const;
  const Value* end() const;
  const Value& operator[](std::size_t index) const;
  ListValue& Append(Value&& value) &;
  ListValue& Append(bool value) &;
  ListValue& Append(int value) &;
  ListValue& Append(std::string_view value) &;
  ListValue& Append(std::string&& value) &;
  ListValue& Append(DictValue&& value) &;
  ListValue Clone() const;
};

class DictValue {
 public:
  DictValue() = default;
  DictValue(DictValue&&) noexcept = default;
  DictValue& operator=(DictValue&&) noexcept = default;
  DictValue(const DictValue&) = delete;
  DictValue& operator=(const DictValue&) = delete;
  bool contains(std::string_view key) const;
  bool empty() const;
  bool Remove(std::string_view key);
  const Value* Find(std::string_view key) const;
  std::optional<bool> FindBool(std::string_view key) const;
  std::optional<int> FindInt(std::string_view key) const;
  const std::string* FindString(std::string_view key) const;
  std::string* FindString(std::string_view key);
  const DictValue* FindDict(std::string_view key) const;
  DictValue* FindDict(std::string_view key);
  const ListValue* FindList(std::string_view key) const;
  ListValue* FindList(std::string_view key);
  Value* Set(std::string_view key, Value&& value) &;
  Value* Set(std::string_view key, bool value) &;
  Value* Set(std::string_view key, int value) &;
  Value* Set(std::string_view key, double value) &;
  Value* Set(std::string_view key, std::string_view value) &;
  Value* Set(std::string_view key, const char* value) &;
  Value* Set(std::string_view key, std::string&& value) &;
  Value* Set(std::string_view key, DictValue&& value) &;
  Value* Set(std::string_view key, ListValue&& value) &;
  template <typename T>
  Value* Set(std::string_view, const T*) & = delete;
  DictValue Clone() const;
};

class ValueView {
 public:
  ValueView(const DictValue& value);  // NOLINT(runtime/explicit)
  ValueView(const ListValue& value);  // NOLINT(runtime/explicit)
  ValueView(const Value& value);      // NOLINT(runtime/explicit)
};

// base/json/*.h
inline constexpr int JSON_PARSE_RFC = 0;
class JSONReader {
 public:
  static std::optional<DictValue> ReadDict(std::string_view json, int options = 0);
};
class JSONWriter {
 public:
  static bool Write(ValueView node, std::string* json);
};

// base/functional/*.h
template <typename Signature>
class OnceCallback;
template <typename Signature>
class RepeatingCallback;
template <typename R, typename... Args>
class OnceCallback<R(Args...)> {
 public:
  OnceCallback() = default;
  OnceCallback(OnceCallback&&) noexcept = default;
  OnceCallback& operator=(OnceCallback&&) noexcept = default;
  OnceCallback(const OnceCallback&) = delete;
  OnceCallback& operator=(const OnceCallback&) = delete;
  explicit operator bool() const { return true; }
  R Run(Args...) &&;
};
template <typename R, typename... Args>
class RepeatingCallback<R(Args...)> {
 public:
  RepeatingCallback() = default;
  RepeatingCallback(const RepeatingCallback&) = default;
  RepeatingCallback& operator=(const RepeatingCallback&) = default;
  RepeatingCallback(RepeatingCallback&&) noexcept = default;
  RepeatingCallback& operator=(RepeatingCallback&&) noexcept = default;
  explicit operator bool() const { return true; }
  R Run(Args...) const;
};
using OnceClosure = OnceCallback<void()>;
using RepeatingClosure = RepeatingCallback<void()>;

// The real BindOnce and BindRepeating deduce the callback type from the
// functor and the arguments bound to it. The stand-in deduces the same thing,
// so a call that binds the wrong number of arguments, or arguments of the
// wrong type, fails here as it would in a Chromium build.
namespace internal {

template <typename T>
struct Unretained {
  T* value;
};
template <typename T>
struct Owned {
  T* value;
};

template <typename... Ts>
struct List {};

template <std::size_t N, typename L>
struct Drop {
  // Binding more arguments than the functor takes names no type, which is
  // what reports it.
};
template <typename... Ts>
struct Drop<0, List<Ts...>> {
  using type = List<Ts...>;
};
template <std::size_t N, typename T, typename... Ts>
  requires(N > 0)
struct Drop<N, List<T, Ts...>> {
  using type = typename Drop<N - 1, List<Ts...>>::type;
};

template <typename F, typename = void>
struct Traits;
template <typename R, typename... Ps>
struct Traits<R (*)(Ps...), void> {
  using Ret = R;
  using Params = List<Ps...>;
};
template <typename R, typename C, typename... Ps>
struct Traits<R (C::*)(Ps...), void> {
  using Ret = R;
  using Params = List<C*, Ps...>;
};
template <typename R, typename C, typename... Ps>
struct Traits<R (C::*)(Ps...) const, void> {
  using Ret = R;
  using Params = List<const C*, Ps...>;
};
template <typename F>
struct Traits<F, std::enable_if_t<std::is_class_v<F>>> {
  using Inner = Traits<decltype(&F::operator()), void>;
  using Ret = typename Inner::Ret;
  // The closure object is not an argument a caller binds.
  using Params = typename Drop<1, typename Inner::Params>::type;
};

template <typename R, typename L>
struct Signature;
template <typename R, typename... Ps>
struct Signature<R, List<Ps...>> {
  using type = R(Ps...);
};

template <typename Functor, std::size_t Bound>
using Remaining = typename Signature<
    typename Traits<std::decay_t<Functor>>::Ret,
    typename Drop<Bound, typename Traits<std::decay_t<Functor>>::Params>::type>::type;

// What base::DoNothing() returns: convertible to any callback whose return
// type is void.
struct DoNothingCallback {
  template <typename... Ps>
  operator OnceCallback<void(Ps...)>() const {  // NOLINT(runtime/explicit)
    return OnceCallback<void(Ps...)>();
  }
  template <typename... Ps>
  operator RepeatingCallback<void(Ps...)>() const {  // NOLINT(runtime/explicit)
    return RepeatingCallback<void(Ps...)>();
  }
};

}  // namespace internal

template <typename T>
internal::Unretained<T> Unretained(T* value) {
  return {value};
}
template <typename T>
internal::Owned<T> Owned(T* value) {
  return {value};
}
// base/functional/bind.h: keeps a reference-counted object alive for as long
// as the callback.
template <typename T>
scoped_refptr<T> RetainedRef(T* value) {
  return scoped_refptr<T>(value);
}
template <typename T>
scoped_refptr<T> RetainedRef(scoped_refptr<T> value) {
  return value;
}

template <typename Functor, typename... Args>
OnceCallback<internal::Remaining<Functor, sizeof...(Args)>> BindOnce(Functor&&, Args&&...) {
  return OnceCallback<internal::Remaining<Functor, sizeof...(Args)>>();
}
template <typename Functor, typename... Args>
RepeatingCallback<internal::Remaining<Functor, sizeof...(Args)>> BindRepeating(Functor&&,
                                                                               Args&&...) {
  return RepeatingCallback<internal::Remaining<Functor, sizeof...(Args)>>();
}
inline constexpr internal::DoNothingCallback DoNothing() {
  return internal::DoNothingCallback();
}

// base/memory/weak_ptr.h
template <typename T>
class WeakPtr {
 public:
  WeakPtr() = default;
  T* get() const { return nullptr; }
  T* operator->() const { return get(); }
  explicit operator bool() const { return false; }
};
template <typename T>
class WeakPtrFactory {
 public:
  explicit WeakPtrFactory(T*) {}
  WeakPtr<T> GetWeakPtr() { return WeakPtr<T>(); }
};

// base/memory/scoped_refptr.h, base/memory/ref_counted.h
template <typename T>
class RefCounted {
 protected:
  RefCounted() = default;
  ~RefCounted() = default;
};
template <typename T>
class RefCountedThreadSafe {
 protected:
  RefCountedThreadSafe() = default;
  ~RefCountedThreadSafe() = default;
};
template <typename T, typename... Args>
scoped_refptr<T> MakeRefCounted(Args&&...) {
  return scoped_refptr<T>();
}

// base/task/*.h
class SequencedTaskRunner;
class SingleThreadTaskRunner : public RefCountedThreadSafe<SingleThreadTaskRunner> {
 public:
  bool PostTask(const Location& from, OnceClosure task);
  void DeleteSoon(const Location& from, const void* object);
};
enum class TaskShutdownBehavior { CONTINUE_ON_SHUTDOWN, SKIP_ON_SHUTDOWN, BLOCK_SHUTDOWN };
enum class SingleThreadTaskRunnerThreadMode { SHARED, DEDICATED };
struct MayBlock {};
struct WithBaseSyncPrimitives {};
class TaskTraits {
 public:
  template <typename... Ts>
  TaskTraits(Ts...) {}  // NOLINT(runtime/explicit)
};
class ThreadPool {
 public:
  static scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunner(
      const TaskTraits& traits,
      SingleThreadTaskRunnerThreadMode mode = SingleThreadTaskRunnerThreadMode::SHARED);
};
template <typename Callback>
Callback BindPostTask(scoped_refptr<SingleThreadTaskRunner>, Callback callback) {
  return std::move(callback);
}

// base/timer/timer.h
class OneShotTimer {
 public:
  void Start(const Location& from, TimeDelta delay, OnceClosure task);
  void Stop();
};

// base/synchronization/waitable_event.h
class WaitableEvent {
 public:
  enum class ResetPolicy { MANUAL, AUTOMATIC };
  enum class InitialState { SIGNALED, NOT_SIGNALED };
  WaitableEvent(ResetPolicy policy = ResetPolicy::MANUAL,
                InitialState state = InitialState::NOT_SIGNALED);
  void Signal();
  bool TimedWait(TimeDelta wait);
};

// base/threading/platform_thread.h
class PlatformThread {
 public:
  static void SetName(const std::string& name);
};

// base/files/*.h
class FilePath {
 public:
  FilePath() = default;
  explicit FilePath(std::string_view path);
};
class ScopedFD {
 public:
  ScopedFD() = default;
  explicit ScopedFD(int fd) : fd_(fd) {}
  ScopedFD(ScopedFD&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  ScopedFD& operator=(ScopedFD&& other) noexcept {
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
  }
  ScopedFD(const ScopedFD&) = delete;
  ScopedFD& operator=(const ScopedFD&) = delete;
  int get() const { return fd_; }
  bool is_valid() const { return fd_ >= 0; }

 private:
  int fd_ = -1;
};

// base/no_destructor.h
template <typename T>
class NoDestructor {
 public:
  template <typename... Args>
  explicit NoDestructor(Args&&... args) : value_(std::forward<Args>(args)...) {}
  T& operator*() { return value_; }
  T* operator->() { return &value_; }

 private:
  T value_;
};

// base/command_line.h
class CommandLine {
 public:
  static CommandLine* ForCurrentProcess();
  bool HasSwitch(std::string_view name) const;
  std::string GetSwitchValueASCII(std::string_view name) const;
};

// base/strings/*.h
std::string NumberToString(std::uint64_t value);
std::string NumberToString(unsigned value);
bool StringToUint64(std::string_view input, std::uint64_t* output);
bool StringToUint(std::string_view input, unsigned* output);
bool IsStringUTF8(std::string_view text);

// base/unguessable_token.h
class UnguessableToken {
 public:
  static const UnguessableToken& Null();
  std::uint64_t GetHighForSerialization() const;
  std::uint64_t GetLowForSerialization() const;
  bool operator==(const UnguessableToken&) const = default;
};

}  // namespace base

namespace ui {
enum PageTransition : std::int32_t { PAGE_TRANSITION_LINK = 0 };
}  // namespace ui

namespace mojo {
class ScopedInterfaceEndpointHandle {};
template <typename T>
class PendingReceiver {
 public:
  PendingReceiver() = default;
  PendingReceiver(PendingReceiver&&) noexcept = default;
  PendingReceiver& operator=(PendingReceiver&&) noexcept = default;
};
template <typename T>
class PendingRemote {
 public:
  PendingRemote() = default;
  PendingRemote(PendingRemote&&) noexcept = default;
  PendingRemote& operator=(PendingRemote&&) noexcept = default;
};
template <typename T>
class PendingAssociatedReceiver {
 public:
  PendingAssociatedReceiver() = default;
  PendingAssociatedReceiver(PendingAssociatedReceiver&&) noexcept = default;
  PendingAssociatedReceiver& operator=(PendingAssociatedReceiver&&) noexcept = default;
};
template <typename T>
class Receiver {
 public:
  explicit Receiver(T* impl) : impl_(impl) {}
  PendingRemote<T> BindNewPipeAndPassRemote();
  void Bind(PendingReceiver<T> receiver);
  void Bind(PendingReceiver<T> receiver, scoped_refptr<base::SingleThreadTaskRunner> runner);
  void set_disconnect_handler(base::OnceClosure handler);
  void reset();
  bool is_bound() const;

 private:
  T* impl_ = nullptr;
};
template <typename T>
class AssociatedReceiver {
 public:
  explicit AssociatedReceiver(T* impl) : impl_(impl) {}
  void Bind(PendingAssociatedReceiver<T> receiver);
  void reset();
  bool is_bound() const;

 private:
  T* impl_ = nullptr;
};
template <typename T>
class Remote {
 public:
  Remote() = default;
  void Bind(PendingRemote<T> remote);
  PendingRemote<T> BindNewPipeAndPassRemote();
  PendingReceiver<T> BindNewPipeAndPassReceiver();
  void set_disconnect_handler(base::OnceClosure handler);
  void reset();
  bool is_bound() const;
  T* get() const;
  T* operator->() const { return get(); }
};
template <typename T>
class AssociatedRemote {
 public:
  AssociatedRemote() = default;
  AssociatedRemote(AssociatedRemote&&) noexcept = default;
  AssociatedRemote& operator=(AssociatedRemote&&) noexcept = default;
  PendingAssociatedReceiver<T> BindNewEndpointAndPassReceiver();
  void reset();
  bool is_bound() const;
  T* get() const;
  T* operator->() const { return get(); }
};
}  // namespace mojo

namespace blink {

class WebFrame {
 public:
  WebFrame* Parent() const;
};
class DocumentToken {
 public:
  const base::UnguessableToken& value() const;
};
class LocalFrameToken {
 public:
  const base::UnguessableToken& value() const;
};
class WebDocument {
 public:
  const DocumentToken& Token() const;
};
class WebLocalFrame : public WebFrame {
 public:
  static WebLocalFrame* FrameForCurrentContext();
  LocalFrameToken GetLocalFrameToken() const;
  WebDocument GetDocument() const;
};
enum class BFCacheStateChange { kStoredToBFCache, kRestoredFromBFCache, kNoChange };

class AssociatedInterfaceRegistry {
 public:
  template <typename Interface>
  using ReceiverBinder = base::RepeatingCallback<void(mojo::PendingAssociatedReceiver<Interface>)>;
  template <typename Interface>
  void AddInterface(const std::common_type_t<ReceiverBinder<Interface>&> binder);
};
class AssociatedInterfaceProvider {
 public:
  template <typename Interface>
  void GetInterface(mojo::AssociatedRemote<Interface>* remote);
};

class Platform {
 public:
  static Platform* Current();
  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const;
};

}  // namespace blink

namespace content {

class BrowserThread {
 public:
  enum ID { UI, IO };
};
scoped_refptr<base::SingleThreadTaskRunner> GetUIThreadTaskRunner(int traits = 0);

class RenderFrame {
 public:
  blink::WebLocalFrame* GetWebFrame();
  blink::AssociatedInterfaceRegistry* GetAssociatedInterfaceRegistry();
};

class RenderFrameObserver {
 public:
  explicit RenderFrameObserver(RenderFrame* frame) : frame_(frame) {}
  virtual ~RenderFrameObserver() = default;
  virtual void OnDestruct() = 0;
  virtual void DidCommitProvisionalLoad(ui::PageTransition) {}
  virtual void DidSetPageLifecycleState(blink::BFCacheStateChange) {}
  RenderFrame* render_frame() const { return frame_; }

 private:
  RenderFrame* frame_ = nullptr;
};

class RenderFrameHost {
 public:
  const blink::DocumentToken& GetDocumentToken() const;
  blink::AssociatedInterfaceProvider* GetRemoteAssociatedInterfaces();
};

class RenderProcessHost {
 public:
  class iterator {
   public:
    bool IsAtEnd() const;
    void Advance();
    RenderProcessHost* GetCurrentValue() const;
  };
  static iterator AllHostsIterator();
  template <typename Callback>
  void ForEachRenderFrameHost(Callback callback) {
    callback(static_cast<RenderFrameHost*>(nullptr));
  }
};

}  // namespace content

#endif  // REB_TOOLS_NATIVE_DEBUGGER_PAUSE_CHROMIUM_STUBS_H_
