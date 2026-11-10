import CryptoKit
import Darwin
import Foundation
import Security

// A ChatGPT subscription through OpenAI token sharing: the researcher signs in
// with ChatGPT in their default browser and allows token sharing, and the
// agent's existing LangGraph loop then calls the same Responses endpoint with
// that access token instead of an API key. It is the sign-in T3 Code's managed
// Codex mode uses (OIDC discovery, dynamic client registration, PKCE S256,
// scope `chatgpt.tokens.use.direct`, resource https://api.openai.com/v1).
//
// Boundaries this file owns:
// - Tokens and the client registration live only in the Keychain and in the
//   one outgoing request that needs them. The web view never sees either.
// - Everything signed in is checked: discovery must name auth.openai.com and
//   keep every endpoint on it, the callback must carry this sign-in's state on
//   the exact loopback path, and the ID token must verify against the
//   issuer's keys with this client as audience and this sign-in's nonce.
// - The callback listener is one-shot, on 127.0.0.1 only, and expires after
//   five minutes.
// Foundation, Security and CryptoKit only, so it compiles into
// tools/check-agent-core.swift.

protocol AgentSecretStore: AnyObject {
  // Presence only. It reads no secret, so it never raises a Keychain prompt.
  func contains(_ account: String) -> Bool
  func read(_ account: String) -> Data?
  @discardableResult func write(_ data: Data, account: String) -> Bool
  func delete(_ account: String)
}

// Generic-password items beside the API keys, under their own accounts.
final class AgentKeychainSecretStore: AgentSecretStore {
  private let service = "com.reverseengineeringbrowser.origintrace.agent"

  private func query(_ account: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
  }

  func contains(_ account: String) -> Bool {
    var attributes = query(account)
    attributes[kSecReturnAttributes as String] = true
    return SecItemCopyMatching(attributes as CFDictionary, nil) == errSecSuccess
  }

  func read(_ account: String) -> Data? {
    var attributes = query(account)
    attributes[kSecReturnData as String] = true
    attributes[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    guard SecItemCopyMatching(attributes as CFDictionary, &result) == errSecSuccess else { return nil }
    return result as? Data
  }

  @discardableResult func write(_ data: Data, account: String) -> Bool {
    let status = SecItemUpdate(query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecSuccess { return true }
    guard status == errSecItemNotFound else { return false }
    var added = query(account)
    added[kSecValueData as String] = data
    added[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
    return SecItemAdd(added as CFDictionary, nil) == errSecSuccess
  }

  func delete(_ account: String) { SecItemDelete(query(account) as CFDictionary) }
}

// Tokens from a stand-in issuer never reach the Keychain.
final class AgentMemorySecretStore: AgentSecretStore {
  private var values: [String: Data] = [:]
  func contains(_ account: String) -> Bool { values[account] != nil }
  func read(_ account: String) -> Data? { values[account] }
  @discardableResult func write(_ data: Data, account: String) -> Bool { values[account] = data; return true }
  func delete(_ account: String) { values.removeValue(forKey: account) }
}

struct AgentChatGPTTokens: Codable, Equatable {
  var clientId: String
  var accessToken: String
  var refreshToken: String?
  var idToken: String?
  // Seconds since 1970.
  var expiresAt: Double
  var earliestRefreshAt: Double?
  var scopes: [String]
  var subject: String
  var issuer: String
}

struct AgentChatGPTRegistration: Codable, Equatable {
  var clientId: String
  var subject: String?
  var email: String?
  var redirectURI: String?
  var sharingEnabled: Bool?
}

struct AgentOIDCEndpoints {
  let issuer: String
  let authorization: URL
  let token: URL
  let keys: URL
  let revocation: URL?
}

@MainActor
final class AgentChatGPTAuth {
  nonisolated static let issuer = "https://auth.openai.com"
  nonisolated static let discoveryURL = URL(string: "https://auth.openai.com/.well-known/openid-configuration")!
  nonisolated static let resource = "https://api.openai.com/v1"
  nonisolated static let requiredScope = "chatgpt.tokens.use.direct"
  nonisolated static let scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
  nonisolated static let tokensAccount = "chatgpt-subscription"
  nonisolated static let registrationAccount = "chatgpt-registration"
  nonisolated static let installAccount = "agent-install-id"
  nonisolated static let signInSeconds: TimeInterval = 300

  private let session: URLSession
  private let store: AgentSecretStore
  private let discovery: URL
  let isStandIn: Bool
  private let openURL: (URL) async -> Bool
  private var endpoints: AgentOIDCEndpoints?
  private var keys: [[String: Any]]?
  private var refreshing: Task<AgentChatGPTTokens, Error>?
  private var listener: AgentLoopbackCallback?

  init(session: URLSession, store: AgentSecretStore, discovery: URL = AgentChatGPTAuth.discoveryURL, isStandIn: Bool = false,
    openURL: @escaping (URL) async -> Bool)
  {
    self.session = session
    self.store = store
    self.discovery = discovery
    self.isStandIn = isStandIn
    self.openURL = openURL
  }

  // A loopback issuer, for tests only. Anything else is ignored, so an
  // environment value cannot send a sign-in to another host.
  nonisolated static func standInDiscovery(_ environment: [String: String]) -> URL? {
    guard let raw = environment["REB_AGENT_OPENAI_DISCOVERY_URL"], let url = URL(string: raw), url.scheme == "http",
      ["127.0.0.1", "localhost", "::1"].contains(url.host ?? ""), url.port != nil, url.user == nil, url.password == nil,
      url.query == nil, url.fragment == nil
    else { return nil }
    return url
  }

  // MARK: Status

  var tokens: AgentChatGPTTokens? {
    store.read(Self.tokensAccount).flatMap { try? JSONDecoder().decode(AgentChatGPTTokens.self, from: $0) }
  }
  private var registration: AgentChatGPTRegistration? {
    store.read(Self.registrationAccount).flatMap { try? JSONDecoder().decode(AgentChatGPTRegistration.self, from: $0) }
  }
  var signInWaiting: Bool { listener != nil }

  // Only a sign-in that allowed token sharing keeps tokens, so presence is
  // the whole answer.
  func status() -> [String: Any] {
    guard store.contains(Self.tokensAccount) else {
      return ["signedIn": false, "waiting": signInWaiting, "reason": "Sign in with ChatGPT to use your subscription."]
    }
    return ["signedIn": true, "waiting": signInWaiting]
  }

  // MARK: Discovery and keys

  private func discover() async throws -> AgentOIDCEndpoints {
    if let endpoints { return endpoints }
    let unreachable = AgentFailure(message: "Could not reach ChatGPT sign-in. Try again.")
    var request = URLRequest(url: discovery)
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    guard let (data, response) = try? await session.data(for: request),
      let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
      let document = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
      let issuer = document["issuer"] as? String,
      let authorization = (document["authorization_endpoint"] as? String).flatMap(URL.init(string:)),
      let token = (document["token_endpoint"] as? String).flatMap(URL.init(string:)),
      let keys = (document["jwks_uri"] as? String).flatMap(URL.init(string:))
    else { throw unreachable }
    let revocation = (document["revocation_endpoint"] as? String).flatMap(URL.init(string:))
    let expected = isStandIn ? Self.origin(discovery) : Self.issuer
    let all = [authorization, token, keys] + (revocation.map { [$0] } ?? [])
    guard issuer == expected, all.allSatisfy({ Self.origin($0) == expected }) else {
      throw AgentFailure(message: "ChatGPT sign-in configuration could not be verified.")
    }
    let found = AgentOIDCEndpoints(issuer: issuer, authorization: authorization, token: token, keys: keys, revocation: revocation)
    endpoints = found
    return found
  }

  nonisolated static func origin(_ url: URL) -> String {
    guard let scheme = url.scheme, let host = url.host else { return "" }
    let port = url.port.map { ":\($0)" } ?? ""
    return "\(scheme)://\(host)\(port)"
  }

  private func signingKeys(_ endpoints: AgentOIDCEndpoints, refresh: Bool) async throws -> [[String: Any]] {
    if let keys, !refresh { return keys }
    guard let (data, response) = try? await session.data(from: endpoints.keys),
      (response as? HTTPURLResponse)?.statusCode == 200,
      let document = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
      let found = document["keys"] as? [[String: Any]]
    else { throw AgentFailure(message: "ChatGPT sign-in could not be verified. Start again.") }
    keys = found
    return found
  }

  // MARK: Sign-in

  func cancelSignIn() { listener?.cancel() }

  func signIn() async throws -> [String: Any] {
    guard listener == nil else { throw AgentFailure(message: "A ChatGPT sign-in is already waiting in your browser.") }
    let endpoints = try await discover()
    let saved = registration
    let previous = tokens
    // A registration from an earlier sign-in is reused, so the same ChatGPT
    // connection is renewed rather than a new one added each time.
    let registered = saved.flatMap { $0.clientId.hasPrefix("oaiapp_") ? $0.clientId : nil }
    let state = Self.randomToken(32), nonce = Self.randomToken(32), verifier = Self.randomToken(64)
    let callback = try AgentLoopbackCallback(state: state)
    listener = callback
    defer {
      callback.close()
      listener = nil
    }
    let redirect = "http://127.0.0.1:\(callback.port)/auth/callback"
    var query: [(String, String)] = [("client_id", registered ?? "dynamic_agent_client")]
    if let registered {
      if let email = saved?.email { query.append(("login_hint", email)) }
      if let hint = previous?.idToken, previous?.clientId == registered { query.append(("id_token_hint", hint)) }
      if saved?.sharingEnabled == false || (previous.map { !$0.scopes.contains(Self.requiredScope) } ?? false) {
        query.append(("prompt", "consent"))
      }
    } else {
      query.append(("agent_name_hint", "Origin Trace"))
    }
    query += [
      ("ext_agent_host_id", "urn:uuid:\(installID())"), ("response_type", "code"), ("redirect_uri", redirect),
      ("scope", Self.scope), ("resource", Self.resource), ("state", state), ("nonce", nonce),
      ("code_challenge_method", "S256"), ("code_challenge", Self.challenge(verifier)),
    ]
    var components = URLComponents(url: endpoints.authorization, resolvingAgainstBaseURL: false)!
    components.percentEncodedQuery = Self.formEncoded(query)
    guard let authorize = components.url, await openURL(authorize) else {
      throw AgentFailure(message: "Could not open your browser for ChatGPT sign-in.")
    }
    let returned = try await callback.wait(timeout: Self.signInSeconds)
    let value = { (name: String) in returned.queryItems?.first(where: { $0.name == name })?.value }
    if let error = value("error") {
      throw AgentFailure(message: error == "access_denied"
        ? "ChatGPT sign-in was declined. Sign in again when you are ready." : "ChatGPT sign-in could not be completed. Start again.")
    }
    let returnedClient = value("client_id")
    guard let code = value("code"), let clientId = registered ?? returnedClient, clientId.hasPrefix("oaiapp_"),
      registered == nil || returnedClient == nil || returnedClient == registered
    else { throw AgentFailure(message: "ChatGPT registration is incomplete. Start sign-in again.") }
    let response: [String: Any]
    do {
      response = try await exchange([
        ("grant_type", "authorization_code"), ("client_id", clientId), ("code", code), ("code_verifier", verifier),
        ("redirect_uri", redirect), ("resource", Self.resource),
      ], endpoints: endpoints)
    } catch let failure as AgentFailure where failure.message.contains("code expired") && registered == nil {
      save(AgentChatGPTRegistration(clientId: clientId, redirectURI: redirect))
      throw failure
    }
    let issued = try Self.tokenResponse(response)
    guard let idToken = issued.idToken else {
      throw AgentFailure(message: "ChatGPT did not return a verified identity. Sign in again.")
    }
    let identity = try await verify(idToken, endpoints: endpoints, audience: clientId, nonce: nonce)
    if registered != nil, let expected = saved?.subject, expected != identity.subject {
      throw AgentFailure(message: "This sign-in returned a different ChatGPT account. Your saved connection is unchanged.")
    }
    let sharing = issued.scopes.contains(Self.requiredScope)
    save(AgentChatGPTRegistration(clientId: clientId, subject: identity.subject, email: identity.email, redirectURI: redirect,
      sharingEnabled: sharing))
    if sharing {
      save(AgentChatGPTTokens(
        clientId: clientId, accessToken: issued.accessToken, refreshToken: issued.refreshToken, idToken: idToken,
        expiresAt: Date().timeIntervalSince1970 + Double(issued.expiresIn), earliestRefreshAt: issued.earliestRefreshAt,
        scopes: issued.scopes, subject: identity.subject, issuer: endpoints.issuer))
    }
    guard sharing else {
      throw AgentFailure(message: "Signed in with ChatGPT, but token sharing is off. Sign in again and allow token sharing, or use an API key.")
    }
    return status()
  }

  private func installID() -> String {
    if let data = store.read(Self.installAccount), let id = String(data: data, encoding: .utf8),
      id.range(of: "^[0-9a-f-]{36}$", options: .regularExpression) != nil
    { return id }
    let id = UUID().uuidString.lowercased()
    store.write(Data(id.utf8), account: Self.installAccount)
    return id
  }

  private func save(_ registration: AgentChatGPTRegistration) {
    if let data = try? JSONEncoder().encode(registration) { store.write(data, account: Self.registrationAccount) }
  }

  private func save(_ tokens: AgentChatGPTTokens) {
    if let data = try? JSONEncoder().encode(tokens) { store.write(data, account: Self.tokensAccount) }
  }

  // MARK: Tokens

  struct Issued {
    let accessToken: String
    let refreshToken: String?
    let idToken: String?
    let expiresIn: Int
    let scopes: [String]
    let earliestRefreshAt: Double?
  }

  nonisolated static func tokenResponse(_ document: [String: Any]) throws -> Issued {
    guard let access = document["access_token"] as? String, !access.isEmpty,
      let type = document["token_type"] as? String, type.lowercased() == "bearer",
      let expires = (document["expires_in"] as? NSNumber)?.intValue, expires > 0,
      let scope = document["scope"] as? String
    else { throw AgentFailure(message: "ChatGPT returned an unsupported connection. Sign in again.") }
    let refresh = (document["refresh_token"] as? String).flatMap { $0.isEmpty ? nil : $0 }
    var earliest: Double?
    if let seconds = (document["earliest_refresh_at"] as? NSNumber)?.doubleValue { earliest = seconds }
    else if let text = document["earliest_refresh_at"] as? String { earliest = ISO8601DateFormatter().date(from: text)?.timeIntervalSince1970 }
    return Issued(accessToken: access, refreshToken: refresh, idToken: document["id_token"] as? String, expiresIn: expires,
      scopes: scope.split(separator: " ").map(String.init), earliestRefreshAt: earliest)
  }

  private func exchange(_ form: [(String, String)], endpoints: AgentOIDCEndpoints) async throws -> [String: Any] {
    var request = URLRequest(url: endpoints.token)
    request.httpMethod = "POST"
    request.timeoutInterval = 20
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = Data(Self.formEncoded(form).utf8)
    guard let (data, response) = try? await session.data(for: request), let http = response as? HTTPURLResponse,
      let document = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else { throw AgentFailure(message: "ChatGPT sign-in is temporarily unavailable. Try again.") }
    if (200..<300).contains(http.statusCode) { return document }
    let error = document["error"] as? String ?? ""
    let grant = form.first(where: { $0.0 == "grant_type" })?.1
    if grant == "refresh_token", ["invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired",
      "refresh_token_invalidated", "refresh_token_reused"].contains(error)
    {
      store.delete(Self.tokensAccount)
      throw AgentFailure(message: "Your ChatGPT connection expired or was disconnected. Sign in again.")
    }
    if error == "invalid_client" { throw AgentFailure(message: "OpenAI rejected this app's ChatGPT registration.") }
    if grant == "authorization_code", error == "invalid_grant" {
      throw AgentFailure(message: "This sign-in code expired. Start again.")
    }
    throw AgentFailure(message: error == "access_denied"
      ? "ChatGPT sign-in was declined. Sign in again when you are ready." : "ChatGPT could not complete sign-in. Try again.")
  }

  private func verify(_ idToken: String, endpoints: AgentOIDCEndpoints, audience: String, nonce: String) async throws
    -> (subject: String, email: String?)
  {
    for refresh in [false, true] {
      let keys = try await signingKeys(endpoints, refresh: refresh)
      do {
        let claims = try AgentJWT.verify(idToken, keys: keys, issuer: endpoints.issuer, audience: audience, nonce: nonce, now: Date())
        return (claims["sub"] as? String ?? "", claims["email"] as? String)
      } catch AgentJWT.Failure.unknownKey where !refresh {
        continue
      } catch {
        break
      }
    }
    throw AgentFailure(message: "ChatGPT sign-in could not be verified. Start again.")
  }

  // The access token for one request, renewed first when it is about to
  // expire. Concurrent requests share one renewal.
  func accessToken() async throws -> String {
    if let refreshing { return try await refreshing.value.accessToken }
    guard let current = tokens else { throw AgentFailure(message: "Sign in with ChatGPT to use your subscription.") }
    guard current.scopes.contains(Self.requiredScope) else {
      throw AgentFailure(message: "Token sharing is off. Sign in with ChatGPT again and allow it.")
    }
    let now = Date().timeIntervalSince1970
    if current.expiresAt - now > 60 { return current.accessToken }
    if let earliest = current.earliestRefreshAt, earliest > now {
      if current.expiresAt > now { return current.accessToken }
      throw AgentFailure(message: "ChatGPT cannot renew this connection yet. Try again shortly.")
    }
    guard let refreshToken = current.refreshToken else {
      store.delete(Self.tokensAccount)
      throw AgentFailure(message: "Your ChatGPT connection expired. Sign in again.")
    }
    let task = Task { @MainActor in try await self.renew(current, refreshToken: refreshToken) }
    refreshing = task
    defer { refreshing = nil }
    return try await task.value.accessToken
  }

  private func renew(_ current: AgentChatGPTTokens, refreshToken: String) async throws -> AgentChatGPTTokens {
    let endpoints = try await discover()
    let response = try await exchange([
      ("grant_type", "refresh_token"), ("client_id", current.clientId), ("refresh_token", refreshToken), ("resource", Self.resource),
    ], endpoints: endpoints)
    let issued = try Self.tokenResponse(response)
    guard let rotated = issued.refreshToken else { throw AgentFailure(message: "ChatGPT returned an invalid renewal. Sign in again.") }
    var renewed = current
    renewed.accessToken = issued.accessToken
    renewed.refreshToken = rotated
    renewed.expiresAt = Date().timeIntervalSince1970 + Double(issued.expiresIn)
    renewed.earliestRefreshAt = issued.earliestRefreshAt
    renewed.scopes = issued.scopes
    guard renewed.scopes.contains(Self.requiredScope) else {
      store.delete(Self.tokensAccount)
      throw AgentFailure(message: "ChatGPT token sharing is no longer allowed. Sign in again.")
    }
    save(renewed)
    return renewed
  }

  // Revokes the refresh token when the issuer offers that, then forgets the
  // tokens. The registration stays, so the next sign-in renews the same
  // connection.
  func signOut() async -> String? {
    guard let current = tokens else { return nil }
    var confirmed = current.refreshToken == nil
    if let refreshToken = current.refreshToken, let endpoints = try? await discover(), let revocation = endpoints.revocation {
      var request = URLRequest(url: revocation)
      request.httpMethod = "POST"
      request.timeoutInterval = 10
      request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
      request.httpBody = Data(Self.formEncoded([
        ("token", refreshToken), ("token_type_hint", "refresh_token"), ("client_id", current.clientId),
      ]).utf8)
      confirmed = ((try? await session.data(for: request))?.1 as? HTTPURLResponse)?.statusCode == 200
    }
    store.delete(Self.tokensAccount)
    return confirmed ? nil : "Signed out on this Mac. OpenAI did not confirm the revocation; disconnect Origin Trace in ChatGPT settings if it is still listed."
  }

  // MARK: Encoding

  nonisolated static func randomToken(_ count: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return base64URL(Data(bytes))
  }

  nonisolated static func challenge(_ verifier: String) -> String { base64URL(Data(SHA256.hash(data: Data(verifier.utf8)))) }

  nonisolated static func base64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  nonisolated static func formEncoded(_ pairs: [(String, String)]) -> String {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._~")
    let encode = { (value: String) in value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
    return pairs.map { "\(encode($0.0))=\(encode($0.1))" }.joined(separator: "&")
  }
}

// MARK: - ID token verification

enum AgentJWT {
  enum Failure: Error {
    case malformed, unknownKey, signature, claims
  }

  static func base64URL(_ text: Substring) -> Data? {
    var value = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while value.count % 4 != 0 { value += "=" }
    return Data(base64Encoded: value)
  }

  // RS256 or ES256 against the issuer's published keys, then the claims.
  static func verify(_ token: String, keys: [[String: Any]], issuer: String, audience: String, nonce: String?, now: Date,
    leeway: TimeInterval = 5) throws -> [String: Any]
  {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, let headerData = base64URL(parts[0]), let payloadData = base64URL(parts[1]),
      let signature = base64URL(parts[2]),
      let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
      let claims = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any],
      let algorithm = header["alg"] as? String, ["RS256", "ES256"].contains(algorithm)
    else { throw Failure.malformed }
    let type = algorithm == "RS256" ? "RSA" : "EC"
    let candidates = keys.filter { $0["kty"] as? String == type && ($0["use"] as? String ?? "sig") == "sig" }
    let kid = header["kid"] as? String
    guard let key = kid.map({ id in candidates.first { $0["kid"] as? String == id } }) ?? (candidates.count == 1 ? candidates.first : nil)
    else { throw Failure.unknownKey }
    let input = Data("\(parts[0]).\(parts[1])".utf8)
    if algorithm == "RS256" {
      guard let modulus = (key["n"] as? String).flatMap({ base64URL(Substring($0)) }),
        let exponent = (key["e"] as? String).flatMap({ base64URL(Substring($0)) }),
        let publicKey = rsaPublicKey(modulus: modulus, exponent: exponent),
        SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, input as CFData, signature as CFData, nil)
      else { throw Failure.signature }
    } else {
      guard key["crv"] as? String == "P-256", let x = (key["x"] as? String).flatMap({ base64URL(Substring($0)) }),
        let y = (key["y"] as? String).flatMap({ base64URL(Substring($0)) }), x.count == 32, y.count == 32,
        let publicKey = try? P256.Signing.PublicKey(x963Representation: Data([0x04]) + x + y),
        let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
        publicKey.isValidSignature(ecdsa, for: input)
      else { throw Failure.signature }
    }
    let time = now.timeIntervalSince1970
    let audiences = (claims["aud"] as? [String]) ?? [(claims["aud"] as? String) ?? ""]
    guard claims["iss"] as? String == issuer, audiences.contains(audience),
      let expires = (claims["exp"] as? NSNumber)?.doubleValue, expires + leeway > time,
      ((claims["nbf"] as? NSNumber)?.doubleValue ?? 0) - leeway <= time,
      let subject = claims["sub"] as? String, !subject.isEmpty,
      nonce == nil || claims["nonce"] as? String == nonce
    else { throw Failure.claims }
    return claims
  }

  // A PKCS#1 RSAPublicKey from a JWK's modulus and exponent.
  static func rsaPublicKey(modulus: Data, exponent: Data) -> SecKey? {
    func length(_ count: Int) -> Data {
      if count < 0x80 { return Data([UInt8(count)]) }
      var bytes: [UInt8] = []
      var value = count
      while value > 0 { bytes.insert(UInt8(value & 0xff), at: 0); value >>= 8 }
      return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
    func integer(_ value: Data) -> Data {
      var bytes = Data(value.drop(while: { $0 == 0 }))
      if bytes.isEmpty || bytes[bytes.startIndex] >= 0x80 { bytes.insert(0, at: bytes.startIndex) }
      return Data([0x02]) + length(bytes.count) + bytes
    }
    let body = integer(modulus) + integer(exponent)
    let der = Data([0x30]) + length(body.count) + body
    let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
    return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil)
  }
}

// MARK: - One-shot loopback callback

// Listens on 127.0.0.1 for exactly one sign-in response on /auth/callback with
// this sign-in's state. Any other request gets a plain error and is ignored.
final class AgentLoopbackCallback: @unchecked Sendable {
  let port: UInt16
  private let fd: Int32
  private let state: String
  private let lock = NSLock()
  private var continuation: CheckedContinuation<URLComponents, Error>?
  private var outcome: Result<URLComponents, Error>?
  private var closed = false

  init(state: String) throws {
    self.state = state
    let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socket >= 0 else { throw AgentFailure(message: "Could not start the local sign-in callback.") }
    _ = fcntl(socket, F_SETFD, FD_CLOEXEC)
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = 0
    let bound = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(socket, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    }
    guard bound == 0, listen(socket, 4) == 0 else {
      Darwin.close(socket)
      throw AgentFailure(message: "Could not start the local sign-in callback.")
    }
    var actual = sockaddr_in()
    var size = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &actual) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(socket, $0, &size) }
    }
    fd = socket
    port = UInt16(bigEndian: actual.sin_port)
    Thread.detachNewThread { [self] in serve() }
  }

  private var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }

  private func serve() {
    while !isClosed {
      var poller = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
      guard poll(&poller, 1, 250) > 0 else { continue }
      let client = accept(fd, nil, nil)
      if client < 0 { continue }
      handle(client)
    }
  }

  private func handle(_ client: Int32) {
    defer { Darwin.close(client) }
    var noSignal: Int32 = 1
    setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var head = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while head.range(of: Data("\r\n\r\n".utf8)) == nil, head.count < 16 * 1024 {
      let count = read(client, &chunk, chunk.count)
      if count <= 0 { break }
      head.append(contentsOf: chunk[0..<count])
    }
    let line = String(decoding: head.prefix(while: { $0 != 0x0D && $0 != 0x0A }), as: UTF8.self).split(separator: " ")
    guard line.count == 3, line[0] == "GET", let target = URLComponents(string: "http://127.0.0.1:\(port)\(line[1])"),
      target.path == "/auth/callback"
    else { return respond(client, status: "404 Not Found", body: "Not found.") }
    lock.lock()
    let answered = outcome != nil
    lock.unlock()
    if answered { return respond(client, status: "410 Gone", body: "Sign-in is no longer active.") }
    guard Self.isCallback(target, state: state) else {
      return respond(client, status: "400 Bad Request", body: "This response does not belong to the active sign-in.")
    }
    respond(client, status: "200 OK", body: Self.page, html: true)
    resolve(.success(target))
  }

  // Exactly one state, matching; exactly one of code or error; at most one
  // client id, shaped like a registered one.
  static func isCallback(_ components: URLComponents, state: String) -> Bool {
    let items = components.queryItems ?? []
    let values = { (name: String) in items.filter { $0.name == name }.compactMap(\.value) }
    let states = values("state"), codes = values("code"), errors = values("error"), clients = values("client_id")
    guard components.fragment == nil, components.user == nil, states == [state],
      (codes.count == 1 && !codes[0].isEmpty && errors.isEmpty) || (errors.count == 1 && !errors[0].isEmpty && codes.isEmpty),
      clients.count <= 1, clients.allSatisfy({ $0.range(of: "^oaiapp_[A-Za-z0-9_-]+$", options: .regularExpression) != nil })
    else { return false }
    return true
  }

  static let page = """
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\
    <meta name="color-scheme" content="light dark"><title>Origin Trace</title>\
    <style>body{font:15px/1.6 system-ui;display:grid;place-items:center;min-height:90vh;margin:0}main{max-width:380px;padding:32px}h1{font-size:20px}</style>\
    </head><body><main><h1>Return to Origin Trace</h1><p>Origin Trace received the ChatGPT sign-in response and is finishing \
    the connection. You can close this tab.</p></main></body></html>
    """

  private func respond(_ client: Int32, status: String, body: String, html: Bool = false) {
    let type = html ? "text/html; charset=utf-8" : "text/plain; charset=utf-8"
    let headers = [
      "HTTP/1.1 \(status)", "Content-Type: \(type)", "Content-Length: \(body.utf8.count)", "Cache-Control: no-store",
      "Referrer-Policy: no-referrer", "X-Content-Type-Options: nosniff",
      "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'", "Connection: close",
    ]
    let data = Data((headers.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    data.withUnsafeBytes { raw in
      var offset = 0
      while offset < raw.count {
        let sent = Darwin.write(client, raw.baseAddress! + offset, raw.count - offset)
        if sent <= 0 { return }
        offset += sent
      }
    }
  }

  private func resolve(_ result: Result<URLComponents, Error>) {
    lock.lock()
    guard outcome == nil else { lock.unlock(); return }
    outcome = result
    let waiting = continuation
    continuation = nil
    lock.unlock()
    waiting?.resume(with: result)
  }

  func wait(timeout: TimeInterval) async throws -> URLComponents {
    DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
      self?.resolve(.failure(AgentFailure(message: "ChatGPT sign-in expired. Start again.")))
    }
    return try await withCheckedThrowingContinuation { continuation in
      lock.lock()
      if let outcome {
        lock.unlock()
        continuation.resume(with: outcome)
        return
      }
      self.continuation = continuation
      lock.unlock()
    }
  }

  func cancel() { resolve(.failure(AgentFailure(message: "ChatGPT sign-in was cancelled."))) }

  func close() {
    lock.lock()
    let wasClosed = closed
    closed = true
    lock.unlock()
    if !wasClosed { Darwin.close(fd) }
  }
}
