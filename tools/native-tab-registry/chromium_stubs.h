// Narrow stand-ins for the pinned Chromium 151 content API that
// native_tab_registry.cc, native_factory_scope.cc and native_tab_of.h call.
// Each signature the overlay overrides or calls matches the pinned header;
// behavior is test-controlled state, not a browser.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#define COMPONENT_EXPORT(name)

namespace base {
template <class T>
class NoDestructor {
 public:
  template <class... Args>
  explicit NoDestructor(Args&&... args) : value_(new T(std::forward<Args>(args)...)) {}
  T& operator*() { return *value_; }
  T* operator->() { return value_; }

 private:
  T* value_;
};

struct UnguessableToken {
  std::uint64_t high = 0, low = 0;
  std::uint64_t GetHighForSerialization() const { return high; }
  std::uint64_t GetLowForSerialization() const { return low; }
};

class CommandLine {
 public:
  static CommandLine* ForCurrentProcess() {
    static CommandLine line;
    return &line;
  }
  bool HasSwitch(const char* name) const { return switches.contains(name); }
  std::set<std::string> switches;
};
}  // namespace base

namespace url {
class Origin {
 public:
  Origin() = default;
  Origin(std::string scheme, std::string host)
      : scheme_(std::move(scheme)), host_(std::move(host)) {}
  const std::string& scheme() const { return scheme_; }
  const std::string& host() const { return host_; }

 private:
  std::string scheme_, host_;
};
}  // namespace url

// The pinned GURL::host() returns a view, so the overlay's ternary with a
// default view must keep compiling.
class GURL {
 public:
  GURL() = default;
  GURL(std::string scheme, std::string host)
      : scheme_(std::move(scheme)), host_(std::move(host)), spec_(scheme_ + "://" + host_ + "/") {}
  bool SchemeIs(std::string_view scheme) const { return scheme_ == scheme; }
  std::string_view host() const { return host_; }
  const std::string& spec() const { return spec_; }

 private:
  std::string scheme_, host_, spec_;
};

namespace blink {
template <int Kind>
struct TestWorkerToken {
  base::UnguessableToken token;
  const base::UnguessableToken& value() const { return token; }
};
using DedicatedWorkerToken = TestWorkerToken<1>;
using SharedWorkerToken = TestWorkerToken<2>;
using ServiceWorkerToken = TestWorkerToken<3>;
using LocalFrameToken = TestWorkerToken<4>;
}  // namespace blink

namespace content {
class ChildProcessId {
 public:
  ChildProcessId() = default;
  explicit ChildProcessId(int value) : value_(value) {}
  int GetUnsafeValue() const { return value_; }

 private:
  int value_ = -1;
};

struct GlobalRenderFrameHostId {
  GlobalRenderFrameHostId() = default;
  GlobalRenderFrameHostId(int child, int routing) : child_id(child), frame_routing_id(routing) {}
  ChildProcessId child_id;
  int frame_routing_id = -2;
};

struct GlobalRenderFrameHostToken {
  int child_id = -1;
  blink::LocalFrameToken frame_token;
};

struct FrameTreeNodeId {
  int id = 0;
  int value() const { return id; }
  explicit operator bool() const { return id != 0; }
};

class WebContents;

// A live frame: registered while it exists, so FromID finds it.
class RenderFrameHost {
 public:
  RenderFrameHost(int child, int routing, base::UnguessableToken token, int tab)
      : child_(child), routing_(routing), token_(token), tab_(tab) {
    Live()[{child, routing}] = this;
  }
  ~RenderFrameHost() { Live().erase({child_, routing_}); }
  RenderFrameHost(const RenderFrameHost&) = delete;
  RenderFrameHost& operator=(const RenderFrameHost&) = delete;

  static RenderFrameHost* FromID(int child, int routing) {
    const auto found = Live().find({child, routing});
    return found == Live().end() ? nullptr : found->second;
  }
  static RenderFrameHost* FromID(const GlobalRenderFrameHostId& id) {
    return FromID(id.child_id.GetUnsafeValue(), id.frame_routing_id);
  }
  GlobalRenderFrameHostToken GetGlobalFrameToken() const { return {child_, {token_}}; }
  FrameTreeNodeId GetFrameTreeNodeId() const { return {tab_}; }

 private:
  static std::map<std::pair<int, int>, RenderFrameHost*>& Live() {
    static std::map<std::pair<int, int>, RenderFrameHost*> live;
    return live;
  }
  int child_, routing_;
  base::UnguessableToken token_;
  int tab_;
};

// Every frame is its own tab's primary main frame here.
class WebContents {
 public:
  static WebContents* FromRenderFrameHost(RenderFrameHost* frame) {
    static WebContents contents;
    contents.main_ = frame;
    return frame ? &contents : nullptr;
  }
  WebContents* GetOutermostWebContents() { return this; }
  RenderFrameHost* GetPrimaryMainFrame() const { return main_; }

 private:
  RenderFrameHost* main_ = nullptr;
};

using DedicatedWorkerCreator = std::variant<GlobalRenderFrameHostId, blink::DedicatedWorkerToken>;
using ServiceWorkerClientInfo =
    std::variant<GlobalRenderFrameHostId, blink::DedicatedWorkerToken, blink::SharedWorkerToken>;

class DedicatedWorkerService {
 public:
  class Observer {
   public:
    virtual ~Observer() = default;
    virtual void OnWorkerCreated(const blink::DedicatedWorkerToken& worker_token,
                                 ChildProcessId worker_process_id,
                                 const url::Origin& security_origin,
                                 DedicatedWorkerCreator creator) = 0;
    virtual void OnBeforeWorkerDestroyed(const blink::DedicatedWorkerToken& worker_token,
                                         DedicatedWorkerCreator creator) = 0;
    virtual void OnFinalResponseURLDetermined(const blink::DedicatedWorkerToken& worker_token,
                                              const GURL& url) = 0;
  };
  void AddObserver(Observer* observer) { observers.push_back(observer); }
  // Token order, so a child can come before its parent.
  void EnumerateDedicatedWorkers(Observer* observer) {
    for (const auto& [token, creator] : existing)
      observer->OnWorkerCreated(token, ChildProcessId(1), url::Origin("https", "a.test"), creator);
  }
  std::vector<Observer*> observers;
  std::vector<std::pair<blink::DedicatedWorkerToken, DedicatedWorkerCreator>> existing;
};

class SharedWorkerService {
 public:
  class Observer {
   public:
    virtual ~Observer() = default;
    virtual void OnWorkerCreated(const blink::SharedWorkerToken& token,
                                 ChildProcessId worker_process_id,
                                 const url::Origin& security_origin,
                                 const base::UnguessableToken& dev_tools_token) = 0;
    virtual void OnBeforeWorkerDestroyed(const blink::SharedWorkerToken& token) = 0;
    virtual void OnClientAdded(const blink::SharedWorkerToken& token,
                               GlobalRenderFrameHostId render_frame_host_id) = 0;
    virtual void OnClientRemoved(const blink::SharedWorkerToken& token,
                                 GlobalRenderFrameHostId render_frame_host_id) = 0;
  };
  void AddObserver(Observer* observer) { observers.push_back(observer); }
  void EnumerateSharedWorkers(Observer*) {}
  std::vector<Observer*> observers;
};

struct ServiceWorkerRunningInfo {
  GURL script_url;
  GURL scope;
  blink::ServiceWorkerToken token;
};

class ServiceWorkerContext;
class ServiceWorkerContextObserver {
 public:
  virtual ~ServiceWorkerContextObserver() = default;
  virtual void OnVersionStartedRunning(int64_t, const ServiceWorkerRunningInfo&) {}
  virtual void OnVersionActivated(int64_t, const GURL&) {}
  virtual void OnControlleeAdded(int64_t, const std::string&, const ServiceWorkerClientInfo&) {}
  virtual void OnControlleeNavigationCommitted(int64_t,
                                               const std::string&,
                                               GlobalRenderFrameHostId) {}
  virtual void OnControlleeRemoved(int64_t, const std::string&) {}
  virtual void OnNoControllees(int64_t, const GURL&) {}
  virtual void OnDestruct(ServiceWorkerContext*) {}
};

class ServiceWorkerContext {
 public:
  void AddObserver(ServiceWorkerContextObserver* observer) { observers.insert(observer); }
  void RemoveObserver(ServiceWorkerContextObserver* observer) { observers.erase(observer); }
  const std::map<int64_t, ServiceWorkerRunningInfo>& GetRunningServiceWorkerInfos() {
    return running;
  }
  std::set<ServiceWorkerContextObserver*> observers;
  std::map<int64_t, ServiceWorkerRunningInfo> running;
};

class StoragePartition {
 public:
  DedicatedWorkerService* GetDedicatedWorkerService() { return &dedicated; }
  SharedWorkerService* GetSharedWorkerService() { return &shared; }
  ServiceWorkerContext* GetServiceWorkerContext() { return &service; }
  DedicatedWorkerService dedicated;
  SharedWorkerService shared;
  ServiceWorkerContext service;
};

class BrowserContext {
 public:
  explicit BrowserContext(bool owned_profile) : owned_(owned_profile) {}
  StoragePartition* GetDefaultStoragePartition() { return &partition_; }
  bool owned() const { return owned_; }

 private:
  bool owned_;
  StoragePartition partition_;
};

class ChildProcessSecurityPolicy {
 public:
  static ChildProcessSecurityPolicy* GetInstance() {
    static ChildProcessSecurityPolicy policy;
    return &policy;
  }
  bool HasWebUIBindings(int) const { return false; }
  std::string GetProcessLockScheme(int) const { return "https"; }
};
}  // namespace content

namespace reb {
// Only the owned-profile test the factory scope and version note make.
class NativeNetworkCaptureSink {
 public:
  static NativeNetworkCaptureSink& Get() {
    static NativeNetworkCaptureSink sink;
    return sink;
  }
  bool IsOwnedContext(content::BrowserContext* context) const {
    return context && context->owned();
  }
};
}  // namespace reb
