import Foundation

// What a native bridge sends its page: events, and the replies to the page's
// requests, in the order native made them. Events reach the page only as the
// answer to its own waiting `events` request, never as a script native runs
// there. WebKit runs such a script as a user gesture and, since 265168@main,
// consumes the page's transient activation when that gesture ends; one that
// ends between a researcher's press and click takes the click's activation,
// and WebKit refuses what the click does, such as a clipboard write. A reply
// only settles the page's own promise.
//
// The page keeps one request waiting and asks again once it has the answer.
// Events made in between wait for that request, and a reply made after them
// waits behind them, so the page sees everything in the order it was made.
// Each document names itself in its request. A navigation retires the
// document on screen: its waiting request is answered with a refusal and a
// late request from it is refused, so nothing meant for the next document
// goes to one that is leaving.
@MainActor
final class NativePageOutbox {
  typealias Reply = (Any?, String?) -> Void

  private enum Item {
    case event(Any)
    case reply(Reply, Any?, String?)
  }

  private static let left = "This document is no longer the application's."
  private var items: [Item] = []
  private var waiting: Reply?
  private var page: String?
  private var retired: Set<String> = []

  // The page's request for events; answered at once when some are waiting.
  func wait(page: String, _ reply: @escaping Reply) {
    guard !retired.contains(page) else { return reply(nil, Self.left) }
    // One request waits at a time: an earlier one is turned away.
    waiting?(nil, "Another request for events took this one's place.")
    waiting = reply
    self.page = page
    flush()
  }

  // Events go only to the document on screen: a bridge posts them only after
  // its navigation finished.
  func post(_ event: Any) {
    items.append(.event(event))
    flush()
  }

  // The reply to one of the page's requests, after any event made before it.
  func answer(_ reply: @escaping Reply, _ value: Any?, _ error: String?) {
    items.append(.reply(reply, value, error))
    flush()
  }

  // A navigation: the document on screen leaves with the events it did not
  // take. Replies still go, each exactly once, as WebKit requires.
  func reset() {
    if let page { retired.insert(page) }
    page = nil
    let pending = items
    items.removeAll()
    for case .reply(let reply, let value, let error) in pending { reply(value, error) }
    waiting?(nil, Self.left)
    waiting = nil
  }

  private func flush() {
    while let first = items.first {
      if case .reply(let reply, let value, let error) = first {
        items.removeFirst()
        reply(value, error)
        continue
      }
      guard let reply = waiting else { return }
      waiting = nil
      let count = items.firstIndex { if case .reply = $0 { true } else { false } } ?? items.count
      let events = items.prefix(count).compactMap { item -> Any? in if case .event(let event) = item { event } else { nil } }
      items.removeFirst(count)
      reply(["events": events], nil)
    }
  }
}
