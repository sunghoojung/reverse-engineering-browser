import CryptoKit
import Darwin
import Foundation
import Security

// Subscription paths against stand-ins, from check-agent-core: the Claude and
// Grok CLI drivers with the stand-in CLIs in tools/agent-cli-stand-in.swift
// and the real `reb-api mcp`, and the ChatGPT token-sharing sign-in against a
// loopback OAuth issuer that checks PKCE, state and nonce.

// A loopback OIDC issuer: discovery, authorize (redirects to the callback),
// token, JWKS and revocation. It signs ID tokens with an RSA key it owns.
final class OAuthStandIn: @unchecked Sendable {
  private let lock = NSLock()
  private let listenFD: Int32
  let port: UInt16
  private let key: SecKey
  private(set) var authorizeQueries: [[String: String]] = []
  private(set) var tokenForms: [[String: String]] = []
  private(set) var revoked: [String] = []
  private var pending: (challenge: String, nonce: String, redirect: String)?
  var wrongIssuer = false
  var wrongNonce = false
  var withoutSharing = false
  var expiresIn = 3600
  var refreshFails = false
  var registeredClient = "oaiapp_standin"
  private var issued = 0

  init() {
    var error: Unmanaged<CFError>?
    key = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, &error)!
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { precondition(bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0) }
    }
    precondition(listen(fd, 16) == 0)
    var bound = sockaddr_in()
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &bound) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &length) }
    }
    port = UInt16(bigEndian: bound.sin_port)
    listenFD = fd
    Thread.detachNewThread { [weak self] in
      while let self {
        let client = accept(self.listenFD, nil, nil)
        if client < 0 { return }
        Thread.detachNewThread { self.serve(client) }
      }
    }
  }

  var origin: String { "http://127.0.0.1:\(port)" }
  var discovery: URL { URL(string: "\(origin)/.well-known/openid-configuration")! }

  private func publicJWK() -> [String: Any] {
    let der = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)! as Data
    // SEQUENCE { INTEGER n, INTEGER e }
    var index = der.startIndex
    func readLength() -> Int {
      let first = der[index]; index += 1
      if first < 0x80 { return Int(first) }
      var value = 0
      for _ in 0..<Int(first & 0x7f) { value = value << 8 | Int(der[index]); index += 1 }
      return value
    }
    index += 1; _ = readLength()
    index += 1; let nLength = readLength(); let n = der[index..<index + nLength]; index += nLength
    index += 1; let eLength = readLength(); let e = der[index..<index + eLength]
    let trim = { (bytes: Data) in Data(bytes.drop(while: { $0 == 0 })) }
    return ["kty": "RSA", "kid": "stand-in", "use": "sig", "alg": "RS256",
      "n": AgentChatGPTAuth.base64URL(trim(Data(n))), "e": AgentChatGPTAuth.base64URL(trim(Data(e)))]
  }

  func idToken(audience: String, nonce: String) -> String {
    let header = AgentChatGPTAuth.base64URL(try! JSONSerialization.data(withJSONObject: ["alg": "RS256", "kid": "stand-in", "typ": "JWT"]))
    let claims: [String: Any] = ["iss": origin, "aud": audience, "sub": "user-standin", "email": "researcher@example.test",
      "nonce": wrongNonce ? "other" : nonce, "exp": Int(Date().timeIntervalSince1970) + 3600, "iat": Int(Date().timeIntervalSince1970)]
    let payload = AgentChatGPTAuth.base64URL(try! JSONSerialization.data(withJSONObject: claims))
    let input = Data("\(header).\(payload)".utf8)
    let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, input as CFData, nil)! as Data
    return "\(header).\(payload).\(AgentChatGPTAuth.base64URL(signature))"
  }

  private func serve(_ client: Int32) {
    defer { close(client) }
    var buffer = Data()
    var chunk = [UInt8](repeating: 0, count: 65536)
    while buffer.range(of: Data("\r\n\r\n".utf8)) == nil {
      let count = read(client, &chunk, chunk.count)
      if count <= 0 { return }
      buffer.append(contentsOf: chunk[0..<count])
    }
    let split = buffer.range(of: Data("\r\n\r\n".utf8))!
    let head = String(decoding: buffer[buffer.startIndex..<split.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
    let requestLine = head[0].components(separatedBy: " ")
    var headers: [String: String] = [:]
    for line in head.dropFirst() {
      guard let colon = line.firstIndex(of: ":") else { continue }
      headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
    }
    var body = Data(buffer[split.upperBound...])
    let length = Int(headers["content-length"] ?? "0") ?? 0
    while body.count < length {
      let count = read(client, &chunk, chunk.count)
      if count <= 0 { return }
      body.append(contentsOf: chunk[0..<count])
    }
    let target = URLComponents(string: "\(origin)\(requestLine[1])")!
    let query = Dictionary((target.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
    let form = Dictionary(String(decoding: body, as: UTF8.self).split(separator: "&").map { pair -> (String, String) in
      let parts = pair.split(separator: "=", maxSplits: 1).map { String($0).removingPercentEncoding ?? "" }
      return (parts[0], parts.count > 1 ? parts[1] : "")
    }, uniquingKeysWith: { a, _ in a })
    let reply = { (status: String, headers: [String], body: String) in
      let text = (["HTTP/1.1 \(status)", "Content-Length: \(body.utf8.count)", "Connection: close"] + headers).joined(separator: "\r\n")
        + "\r\n\r\n" + body
      let data = Data(text.utf8)
      _ = data.withUnsafeBytes { write(client, $0.baseAddress, $0.count) }
    }
    let json = { (status: String, object: Any) in
      reply(status, ["Content-Type: application/json"], String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self))
    }
    lock.lock(); defer { lock.unlock() }
    switch target.path {
    case "/.well-known/openid-configuration":
      let issuer = wrongIssuer ? "https://auth.example.invalid" : origin
      json("200 OK", ["issuer": issuer, "authorization_endpoint": "\(origin)/authorize", "token_endpoint": "\(origin)/token",
        "jwks_uri": "\(origin)/jwks", "revocation_endpoint": "\(origin)/revoke"])
    case "/jwks":
      json("200 OK", ["keys": [publicJWK()]])
    case "/authorize":
      authorizeQueries.append(query)
      pending = (query["code_challenge"] ?? "", query["nonce"] ?? "", query["redirect_uri"] ?? "")
      let redirect = "\(query["redirect_uri"] ?? "")?code=code-1&state=\(query["state"] ?? "")&client_id=\(registeredClient)"
      reply("302 Found", ["Location: \(redirect)"], "")
    case "/token":
      tokenForms.append(form)
      let scope = withoutSharing ? "openid profile email offline_access" : AgentChatGPTAuth.scope
      if form["grant_type"] == "authorization_code" {
        guard let pending, form["code"] == "code-1", form["redirect_uri"] == pending.redirect,
          AgentChatGPTAuth.challenge(form["code_verifier"] ?? "") == pending.challenge,
          form["resource"] == AgentChatGPTAuth.resource, form["client_id"] == registeredClient
        else { return json("400 Bad Request", ["error": "invalid_grant"]) }
        issued += 1
        json("200 OK", ["access_token": "access-\(issued)", "refresh_token": "refresh-\(issued)", "token_type": "Bearer",
          "expires_in": expiresIn, "scope": scope, "id_token": idToken(audience: registeredClient, nonce: pending.nonce)])
      } else if form["grant_type"] == "refresh_token" {
        guard !refreshFails, form["refresh_token"] == "refresh-\(issued)" else { return json("400 Bad Request", ["error": "invalid_grant"]) }
        issued += 1
        json("200 OK", ["access_token": "access-\(issued)", "refresh_token": "refresh-\(issued)", "token_type": "bearer",
          "expires_in": 3600, "scope": scope])
      } else {
        json("400 Bad Request", ["error": "unsupported_grant_type"])
      }
    case "/revoke":
      revoked.append(form["token"] ?? "")
      reply("200 OK", [], "")
    default:
      reply("404 Not Found", [], "")
    }
  }

  func reset() {
    lock.lock(); defer { lock.unlock() }
    wrongIssuer = false; wrongNonce = false; withoutSharing = false; expiresIn = 3600; refreshFails = false
  }
}

@MainActor
enum AgentSubscriptionChecks {
  static func waitFor(_ label: String, timeout: TimeInterval = 20, _ condition: () -> Bool) async {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() {
      check(Date() < deadline, "timed out: \(label)")
      try? await Task.sleep(nanoseconds: 20_000_000)
    }
  }

  static func invocation(_ directory: URL, _ name: String) -> [String: Any] {
    let data = (try? Data(contentsOf: directory.appendingPathComponent("stand-in-\(name).json"))) ?? Data()
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
  }

  static func alive(_ pid: pid_t) -> Bool { kill(pid, 0) == 0 }

  static func run(api: URL, endpoint: URL, root: URL) async {
    await checkJWT()
    await checkChatGPT()
    await checkCLIs(api: api, endpoint: endpoint, root: root)
  }

  // MARK: ID tokens

  static func checkJWT() async {
    let signing = P256.Signing.PrivateKey()
    let point = signing.publicKey.x963Representation
    let jwk: [String: Any] = ["kty": "EC", "crv": "P-256", "kid": "ec", "x": AgentChatGPTAuth.base64URL(point[1..<33]),
      "y": AgentChatGPTAuth.base64URL(point[33..<65])]
    func token(_ claims: [String: Any], kid: String = "ec") -> String {
      let header = AgentChatGPTAuth.base64URL(try! JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": kid]))
      let payload = AgentChatGPTAuth.base64URL(try! JSONSerialization.data(withJSONObject: claims))
      let signature = try! signing.signature(for: Data("\(header).\(payload)".utf8))
      return "\(header).\(payload).\(AgentChatGPTAuth.base64URL(signature.rawRepresentation))"
    }
    let now = Date()
    let good: [String: Any] = ["iss": "https://issuer.test", "aud": ["oaiapp_x", "other"], "sub": "s", "nonce": "n",
      "exp": now.timeIntervalSince1970 + 60]
    check((try? AgentJWT.verify(token(good), keys: [jwk], issuer: "https://issuer.test", audience: "oaiapp_x", nonce: "n", now: now)) != nil,
      "an ES256 ID token verifies")
    for (label, claims) in [
      ("issuer", good.merging(["iss": "https://evil.test"]) { $1 }), ("audience", good.merging(["aud": "oaiapp_y"]) { $1 }),
      ("nonce", good.merging(["nonce": "m"]) { $1 }), ("expiry", good.merging(["exp": now.timeIntervalSince1970 - 60]) { $1 }),
      ("subject", good.merging(["sub": ""]) { $1 }),
    ] {
      check((try? AgentJWT.verify(token(claims), keys: [jwk], issuer: "https://issuer.test", audience: "oaiapp_x", nonce: "n", now: now)) == nil,
        "an ID token with the wrong \(label) is refused")
    }
    var tampered = token(good)
    tampered.replaceSubrange(tampered.index(tampered.endIndex, offsetBy: -6)..<tampered.endIndex, with: "AAAAAA")
    check((try? AgentJWT.verify(tampered, keys: [jwk], issuer: "https://issuer.test", audience: "oaiapp_x", nonce: "n", now: now)) == nil,
      "a bad signature is refused")
    do {
      _ = try AgentJWT.verify(token(good, kid: "missing"), keys: [jwk], issuer: "https://issuer.test", audience: "oaiapp_x", nonce: "n", now: now)
      check(false, "an unknown key id is refused")
    } catch AgentJWT.Failure.unknownKey {
    } catch { check(false, "an unknown key id is reported as such") }
    let unsigned = "\(AgentChatGPTAuth.base64URL(Data(#"{"alg":"none"}"#.utf8))).\(AgentChatGPTAuth.base64URL(Data("{}".utf8)))."
    check((try? AgentJWT.verify(unsigned, keys: [jwk], issuer: "https://issuer.test", audience: "oaiapp_x", nonce: nil, now: now)) == nil,
      "alg none is refused")
    print("PASS agent subscriptions: ID token signature and claim checks")
  }

  // MARK: ChatGPT token sharing

  static func checkChatGPT() async {
    check(AgentChatGPTAuth.standInDiscovery(["REB_AGENT_OPENAI_DISCOVERY_URL": "http://127.0.0.1:9/.well-known/openid-configuration"]) != nil,
      "a loopback issuer is a stand-in")
    check(AgentChatGPTAuth.standInDiscovery(["REB_AGENT_OPENAI_DISCOVERY_URL": "https://auth.example/.well-known/openid-configuration"]) == nil,
      "a remote issuer is never a stand-in")
    var good = URLComponents(string: "http://127.0.0.1:5/auth/callback?code=c&state=s&client_id=oaiapp_a")!
    check(AgentLoopbackCallback.isCallback(good, state: "s"), "a well-formed callback is accepted")
    for raw in ["?code=c&state=t", "?code=c&state=s&state=s", "?code=c&error=e&state=s", "?state=s", "?code=c&state=s&client_id=evil",
      "?code=c&state=s&client_id=oaiapp_a&client_id=oaiapp_b"]
    {
      good = URLComponents(string: "http://127.0.0.1:5/auth/callback\(raw)")!
      check(!AgentLoopbackCallback.isCallback(good, state: "s"), "callback refused: \(raw)")
    }

    let issuer = OAuthStandIn()
    let session = URLSession(configuration: .ephemeral)
    // The "browser": follows the authorize redirect to the loopback callback,
    // after first sending a forged response the listener must ignore.
    let browser: (URL) async -> Bool = { url in
      final class NoRedirect: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
          newRequest request: URLRequest) async -> URLRequest? { nil }
      }
      Task.detached {
        let noRedirect = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
        guard let (_, response) = try? await noRedirect.data(from: url),
          let location = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Location"),
          var forged = URLComponents(string: location)
        else { return }
        forged.queryItems = forged.queryItems?.map { $0.name == "state" ? URLQueryItem(name: "state", value: "forged") : $0 }
        let forgedStatus = ((try? await URLSession.shared.data(from: forged.url!))?.1 as? HTTPURLResponse)?.statusCode
        check(forgedStatus == 400, "a callback with another state is refused (\(String(describing: forgedStatus)))")
        let other = URL(string: location.replacingOccurrences(of: "/auth/callback", with: "/other"))!
        let otherStatus = ((try? await URLSession.shared.data(from: other))?.1 as? HTTPURLResponse)?.statusCode
        check(otherStatus == 404, "another path on the listener is refused")
        _ = try? await URLSession.shared.data(from: URL(string: location)!)
      }
      return true
    }
    let store = AgentMemorySecretStore()
    let auth = AgentChatGPTAuth(session: session, store: store, discovery: issuer.discovery, isStandIn: true, openURL: browser)
    check(auth.status()["signedIn"] as? Bool == false, "signed out at first")
    do {
      let status = try await auth.signIn()
      check(status["signedIn"] as? Bool == true, "sign-in completes")
    } catch { check(false, "sign-in failed: \(error)") }
    let query = issuer.authorizeQueries.last ?? [:]
    check(query["client_id"] == "dynamic_agent_client" && query["agent_name_hint"] == "Origin Trace", "first sign-in registers dynamically")
    check(query["scope"] == AgentChatGPTAuth.scope && query["resource"] == AgentChatGPTAuth.resource, "scope and resource are requested")
    check(query["code_challenge_method"] == "S256" && (query["state"]?.count ?? 0) >= 43 && (query["nonce"]?.count ?? 0) >= 43,
      "PKCE S256, state and nonce are sent")
    check(query["ext_agent_host_id"]?.hasPrefix("urn:uuid:") == true, "a stable install id names this host")
    check((query["redirect_uri"] ?? "").range(of: "^http://127\\.0\\.0\\.1:[0-9]+/auth/callback$", options: .regularExpression) != nil,
      "the callback is loopback only")
    let saved = auth.tokens
    check(saved?.accessToken == "access-1" && saved?.clientId == "oaiapp_standin" && saved?.subject == "user-standin", "tokens are kept")
    check(store.read(AgentChatGPTAuth.registrationAccount) != nil, "the registration is kept")
    let token = try? await auth.accessToken()
    check(token == "access-1", "a fresh access token is used as is")

    // The token travels on the fixed Responses route and nowhere else.
    let route = AgentProviderRoute.resolve("https://api.openai.com/v1/responses", method: "POST", standIn: nil)!
    let request = try! route.request(headers: ["authorization": "Bearer page"], body: Data(#"{"model":"m"}"#.utf8), key: token)
    check(request.value(forHTTPHeaderField: "Authorization") == "Bearer access-1" && request.url?.host == "api.openai.com",
      "the access token replaces the page's credential on the Responses route")
    check(agentRedactedKeys("Bearer abcdefghijklmnop and \(issuer.idToken(audience: "a", nonce: "b"))") == "Bearer [token] and [token]",
      "access and ID tokens are scrubbed from error text")

    // A second sign-in reuses the registration.
    do {
      _ = try await auth.signIn()
      let second = issuer.authorizeQueries.last ?? [:]
      check(second["client_id"] == "oaiapp_standin" && second["agent_name_hint"] == nil && second["login_hint"] == "researcher@example.test",
        "a later sign-in renews the same registration")
      check(second["id_token_hint"] != nil, "it carries the previous ID token as a hint")
    } catch { check(false, "second sign-in failed: \(error)") }

    // Renewal near expiry, then a refused renewal asks for a new sign-in.
    issuer.expiresIn = 30
    _ = try? await auth.signIn()
    let before = auth.tokens?.accessToken
    let renewed = try? await auth.accessToken()
    check(before != nil && renewed != nil && renewed != before && issuer.tokenForms.last?["grant_type"] == "refresh_token",
      "an access token about to expire is renewed (\(String(describing: before)) to \(String(describing: renewed)))")
    check(auth.tokens?.accessToken == renewed && auth.tokens?.refreshToken != nil, "the renewal is kept")
    check(issuer.tokenForms.last?["resource"] == AgentChatGPTAuth.resource, "renewal names the resource")
    var expired = auth.tokens!
    expired.expiresAt = Date().timeIntervalSince1970 - 10
    store.write(try! JSONEncoder().encode(expired), account: AgentChatGPTAuth.tokensAccount)
    issuer.refreshFails = true
    do {
      _ = try await auth.accessToken()
      check(false, "a refused renewal fails")
    } catch {
      check("\(error.localizedDescription)".contains("Sign in again"), "a refused renewal asks to sign in again: \(error)")
    }
    check(auth.tokens == nil, "a refused renewal forgets the tokens")
    issuer.reset()

    // Token sharing not allowed, a forged issuer and a wrong nonce all fail.
    issuer.withoutSharing = true
    do { _ = try await auth.signIn(); check(false, "sign-in without token sharing fails") }
    catch { check(error.localizedDescription.contains("token sharing is off"), "without sharing the reason is named: \(error)") }
    check(auth.status()["signedIn"] as? Bool != true, "a sign-in without sharing is not usable")
    issuer.reset()
    issuer.wrongNonce = true
    do { _ = try await auth.signIn(); check(false, "a wrong nonce fails") }
    catch { check(error.localizedDescription.contains("could not be verified"), "a wrong nonce is refused: \(error)") }
    issuer.reset()
    let forged = OAuthStandIn()
    forged.wrongIssuer = true
    let other = AgentChatGPTAuth(session: session, store: AgentMemorySecretStore(), discovery: forged.discovery, isStandIn: true, openURL: browser)
    do { _ = try await other.signIn(); check(false, "a forged issuer fails") }
    catch { check(error.localizedDescription.contains("could not be verified"), "an issuer that is not the discovery origin is refused") }

    // Sign out revokes the refresh token and forgets the tokens.
    _ = try? await auth.signIn()
    let refresh = auth.tokens?.refreshToken
    let notice = await auth.signOut()
    check(notice == nil && issuer.revoked.last == refresh && auth.tokens == nil, "sign out revokes and forgets")
    print("PASS agent subscriptions: ChatGPT token sharing sign-in, PKCE, callback checks, renewal, refusal and sign out (stand-in issuer)")
  }

  // MARK: Claude and Grok CLIs

  final class Rows: @unchecked Sendable {
    var all: [[String: Any]] = []
    func of(_ type: String, turn: String? = nil) -> [[String: Any]] {
      all.filter { $0["type"] as? String == type && (turn == nil || $0["turnId"] as? String == turn) }
    }
    func ended(_ turn: String) -> Bool { !of("turnEnd", turn: turn).isEmpty }
  }

  static func checkCLIs(api: URL, endpoint: URL, root: URL) async {
    let me = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let cliRoot = root.appendingPathComponent("agent-cli", isDirectory: true)
    var environment = ProcessInfo.processInfo.environment
    environment["ANTHROPIC_API_KEY"] = "sk-ant-must-not-pass"
    environment["ANTHROPIC_BASE_URL"] = "https://evil.example"
    environment["XAI_API_KEY"] = "xai-must-not-pass-0000"
    environment["GROK_OAUTH2_REFERRER"] = "t3code"
    let configuration = { (provider: AgentProviderKind, effects: Bool) in
      AgentSession.Configuration(provider: provider, auth: .subscription, model: provider == .grok ? "grok-test" : "claude-test",
        apiExecutable: api, apiBaseURL: endpoint, allowEffects: effects, transcriptDirectory: root.appendingPathComponent("cli-transcripts"))
    }

    for provider in [AgentProviderKind.claude, .grok] {
      let label = provider.label
      let directory = try! AgentCLILocator.workingDirectory(provider, root: cliRoot)
      check((try! FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as! NSNumber).intValue == 0o700,
        "\(label): the CLI folder is user-only")
      let status = provider == .claude
        ? await AgentCLIStatus.claude(me, environment: environment, directory: directory)
        : await AgentCLIStatus.grok(me, environment: environment, directory: directory)
      check(status["signedIn"] as? Bool == true, "\(label): sign-in state is read from the CLI: \(status)")
      check(!json(status).contains("researcher@example.test"), "\(label): the account email does not leave the status check")
      if provider == .claude {
        check(status["plan"] as? String == "max", "Claude: the plan is reported")
        let models = await AgentCLIStatus.claudeModels(me, environment: environment, directory: directory)
        check(models == ["default", "claude-test"], "Claude: models come from the CLI's initialize response: \(models)")
      } else {
        check(status["models"] as? [String] == ["grok-test", "grok-other"] && status["defaultModel"] as? String == "grok-test",
          "Grok: models come from grok models")
      }

      for effects in [false, true] {
        let events = Rows()
        let session = AgentSession(emit: { _ in })
        session.setPanelVisible(true)
        try! await session.enable(configuration(provider, effects), sessionKey: "cli-\(provider.rawValue)-\(effects)")
        check(!session.childIsRunning, "\(label): native lists the tools, then leaves the tool server to the CLI")
        let type: AgentCLIDriver.Type = provider == .grok ? AgentGrokDriver.self : AgentClaudeDriver.self
        let driver = type.init(provider: provider, executable: me, workingDirectory: directory, configuration: configuration(provider, effects),
          tools: session.tools, listedToolNames: session.listedToolNames, environment: environment, emit: { events.all.append($0) })
        check(!driver.isRunning, "\(label): enabling starts no CLI")
        if provider == .grok {
          try? FileManager.default.removeItem(at: directory.appendingPathComponent(".grok"))
        }

        // A structural read runs without asking, through the real tool server.
        try! await driver.send(turnId: "r\(effects)", text: "What loaded? SCENARIO:read")
        await waitFor("\(label) read turn") { events.ended("r\(effects)") }
        let tools = events.of("tool", turn: "r\(effects)")
        check(tools.map { $0["state"] as? String ?? "" } == ["running", "done"], "\(label): the read is shown running, then done: \(tools)")
        check(tools.last?["name"] as? String == "get_session_summary", "\(label): the tool row names the reb-api tool")
        let result = tools.last?["result"] as? String ?? ""
        check(result.contains("session") && !result.contains("SECRET_SOURCE_BODY"), "\(label): the real tool server answered without content")
        check(events.of("approval").isEmpty, "\(label): a structural read does not ask")
        let text = events.of("text", turn: "r\(effects)").map { $0["delta"] as? String ?? "" }.joined()
        check(text.contains("Answer [cite session=9 artifact=5]."), "\(label): model text streams to the panel: \(text)")
        check(!events.of("assistantDone", turn: "r\(effects)").isEmpty, "\(label): finished text is reported for the transcript")
        check(events.all.allSatisfy { $0["cli"] as? Bool == true }, "\(label): every row is marked as coming from the CLI")
        let end = events.of("turnEnd", turn: "r\(effects)").last ?? [:]
        check((end["inputTokens"] as? Int ?? 0) > 0 && (end["outputTokens"] as? Int ?? 0) > 0, "\(label): usage is reported")
        check(driver.isRunning, "\(label): the CLI keeps the conversation between turns")

        let started = invocation(directory, provider == .claude ? "claude" : "grok")
        let arguments = started["arguments"] as? [String] ?? []
        let childEnvironment = started["environment"] as? [String: String] ?? [:]
        check(started["ownGroup"] as? Bool == true, "\(label): the CLI runs in its own process group")
        for name in ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "XAI_API_KEY", "GROK_OAUTH2_REFERRER"] {
          check(childEnvironment[name] == nil, "\(label): \(name) does not reach the CLI")
        }
        if provider == .claude {
          for flag in ["--strict-mcp-config", "--no-session-persistence", "--disable-slash-commands", "--include-partial-messages"] {
            check(arguments.contains(flag), "Claude: \(flag)")
          }
          check(!arguments.contains("--bare"), "Claude: --bare would drop the claude.ai login")
          let pair = { (flag: String) in arguments.firstIndex(of: flag).map { arguments[$0 + 1] } }
          check(pair("--tools") == "" && pair("--setting-sources") == "" && pair("--permission-prompt-tool") == "stdio",
            "Claude: no built-in tools, no settings sources, permission prompts come here")
          check(pair("--system-prompt") == agentSystemPrompt && pair("--model") == "claude-test", "Claude: the shared prompt and model")
          let hidden = pair("--disallowed-tools") ?? ""
          check(hidden.contains("mcp__reb__get_artifact_content") && !hidden.contains("mcp__reb__get_events"),
            "Claude: tools the agent may not use are hidden from the model")
          let mcp = (try? JSONSerialization.jsonObject(with: Data((pair("--mcp-config") ?? "").utf8))) as? [String: Any]
          let servers = mcp?["mcpServers"] as? [String: Any] ?? [:]
          let rebArguments = (servers["reb"] as? [String: Any])?["args"] as? [String] ?? []
          check(Array(servers.keys) == ["reb"] && rebArguments.contains("--omit-content")
            && rebArguments.contains("--allow-effects") == effects, "Claude: one reb-api server with the graph's gates")
        } else {
          for flag in ["--disable-web-search", "--no-subagents", "--no-leader", "stdio"] { check(arguments.contains(flag), "Grok: \(flag)") }
          check(arguments.firstIndex(of: "--permission-mode").map { arguments[$0 + 1] } == "default", "Grok: it asks before every tool")
          check(arguments.firstIndex(of: "-m").map { arguments[$0 + 1] } == "grok-test", "Grok: the model is passed")
          for (name, value) in AgentGrokDriver.isolation { check(childEnvironment[name] == value, "Grok: \(name)=\(value)") }
          let config = (try? String(contentsOf: directory.appendingPathComponent(".grok/config.toml"), encoding: .utf8)) ?? ""
          check(config.contains("[mcp_servers.\"user-server\"]") && config.contains("enabled = false") && !config.contains("claude-compat"),
            "Grok: the researcher's own MCP server is replaced by a disabled stub")
          let profile = (try? String(contentsOf: directory.appendingPathComponent("origin-trace-agent.md"), encoding: .utf8)) ?? ""
          check(profile.contains("tools:\n  - search_tool\n  - use_tool\n---") && profile.contains("agents_md: false")
            && profile.contains(agentSystemPrompt), "Grok: the agent profile allows only the two MCP tools")
        }

        // An action asks, Deny refuses it, Allow once runs it. Only with effects.
        try! await driver.send(turnId: "a\(effects)", text: "Pause capture SCENARIO:action")
        if effects {
          await waitFor("\(label) approval") { !events.of("approval", turn: "a\(effects)").isEmpty || events.ended("a\(effects)") }
          let approval = events.of("approval", turn: "a\(effects)").first ?? [:]
          check(approval["name"] as? String == "capture_action", "\(label): an action waits for a decision")
          check(!driver.decide(callId: "unknown", allow: true), "\(label): an unknown decision is ignored")
          check(driver.decide(callId: approval["callId"] as? String ?? "", allow: false), "\(label): Deny answers the waiting call")
          await waitFor("\(label) denied turn") { events.ended("a\(effects)") }
          check(events.of("tool", turn: "a\(effects)").last?["state"] as? String == "denied", "\(label): a denied action is shown denied")
          try! await driver.send(turnId: "b\(effects)", text: "Pause capture SCENARIO:action")
          await waitFor("\(label) second approval") { !events.of("approval", turn: "b\(effects)").isEmpty }
          let second = events.of("approval", turn: "b\(effects)").first ?? [:]
          _ = driver.decide(callId: second["callId"] as? String ?? "", allow: true)
          await waitFor("\(label) allowed turn") { events.ended("b\(effects)") }
          let ran = events.of("tool", turn: "b\(effects)").map { $0["state"] as? String ?? "" }
          check(ran.first == "running" && ran.count == 2, "\(label): Allow once runs that call: \(ran)")
        } else {
          await waitFor("\(label) refused action") { events.ended("a\(effects)") }
          check(events.of("approval", turn: "a\(effects)").isEmpty, "\(label): with actions off nothing asks")
          check(events.of("tool", turn: "a\(effects)").last?["state"] as? String == "refused", "\(label): an unlisted action is refused")
        }
        let decisions = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        let answered = decisions.filter { $0.hasPrefix(provider == .claude ? "stand-in-decision" : "stand-in-outcome") }.compactMap {
          (try? JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent($0)))) as? [String: Any]
        }
        check(!answered.contains { json($0).contains("always") }, "\(label): no call is ever answered with a standing grant")

        // Stop kills the CLI and everything it started, even outside its group.
        try! await driver.send(turnId: "h\(effects)", text: "Long one SCENARIO:hold")
        let helpers = directory.appendingPathComponent("stand-in-helpers")
        try? FileManager.default.removeItem(at: helpers)
        await waitFor("\(label) helpers") { FileManager.default.fileExists(atPath: helpers.path) }
        let pids = ((try? String(contentsOf: helpers, encoding: .utf8)) ?? "").split(separator: " ").compactMap { pid_t($0) }
        let cliPid = driver.process?.pid ?? 0
        check(pids.count == 2 && pids.allSatisfy(alive), "\(label): the stand-in started two helpers")
        driver.cancel()
        check(events.of("turnEnd", turn: "h\(effects)").last?["stopped"] as? Bool == true, "\(label): Stop ends the turn as stopped")
        check(!driver.isRunning, "\(label): Stop ends the CLI")
        await waitFor("\(label) process group gone", timeout: 5) { !alive(cliPid) && !pids.contains(where: alive) }

        // The next question starts a new conversation and says so.
        try! await driver.send(turnId: "n\(effects)", text: "Again SCENARIO:read")
        await waitFor("\(label) restart") { events.ended("n\(effects)") }
        check(events.of("notice", turn: "n\(effects)").contains { ($0["text"] as? String ?? "").contains("new \(label) CLI conversation") },
          "\(label): a restarted CLI says the conversation is new")

        // A built-in tool or a foreign permission ends the CLI.
        let foreign = provider == .claude ? ["foreign", "init-foreign", "api-key"] : ["builtin", "foreign-permission"]
        for scenario in foreign {
          let id = "\(scenario)-\(effects)"
          try! await driver.send(turnId: id, text: "Try SCENARIO:\(scenario)")
          await waitFor("\(label) \(scenario)") { events.ended(id) }
          let message = events.of("error", turn: id).last?["message"] as? String ?? ""
          check(message.contains("stopped"), "\(label): \(scenario) stops the CLI: \(message)")
          check(!driver.isRunning, "\(label): \(scenario) leaves no CLI running")
        }
        if provider == .claude {
          try! await driver.send(turnId: "m\(effects)", text: "Noise SCENARIO:malformed")
          await waitFor("Claude malformed") { events.ended("m\(effects)") }
          check(events.of("error", turn: "m\(effects)").contains { ($0["message"] as? String ?? "").contains("could not read") },
            "Claude: unreadable output is a visible error row")
          check(events.of("error", turn: "m\(effects)").count == 1 && driver.isRunning, "Claude: and the turn still completes")
        } else {
          FileManager.default.createFile(atPath: directory.appendingPathComponent("stand-in-leak").path, contents: Data())
          try! await driver.send(turnId: "l\(effects)", text: "Again SCENARIO:read")
          await waitFor("Grok leak") { events.ended("l\(effects)") }
          check((events.of("error", turn: "l\(effects)").last?["message"] as? String ?? "").contains("MCP servers from your settings"),
            "Grok: a server merged from the researcher's settings stops the CLI")
          try? FileManager.default.removeItem(at: directory.appendingPathComponent("stand-in-leak"))
          FileManager.default.createFile(atPath: directory.appendingPathComponent("stand-in-sticky").path, contents: Data())
          try! await driver.send(turnId: "s\(effects)", text: "Again SCENARIO:read")
          await waitFor("Grok sticky") { events.ended("s\(effects)") }
          check((events.of("error", turn: "s\(effects)").last?["message"] as? String ?? "").contains("was not started"),
            "Grok: a server the stub cannot turn off keeps Grok from starting")
          try? FileManager.default.removeItem(at: directory.appendingPathComponent("stand-in-sticky"))
        }
        driver.shutdown()
        session.disable()
      }
      print("PASS agent subscriptions: \(label) CLI driver, isolation flags and environment, structural reads, Allow once and Deny, refusals, Stop with process-group kill (stand-in CLI, real reb-api)")
    }
  }
}
