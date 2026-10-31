import Foundation
import Security

// A paired release names the exact browser build it was accepted with. The
// browser version cannot identify that build: every build from one Brave pin
// reports the same version. The code directory hash of the signed main
// executable also seals the bundle's nested code and resources, so it changes
// with any rebuilt or modified browser and survives ZIP extraction and moving
// the app. This is a compatibility check, not a security boundary: it reads the
// recorded signature without validating every sealed file.
enum BrowserPairing {
  static let releaseTypeKey = "OriginTraceReleaseType"
  static let pairedBrowserKey = "OriginTracePairedBrowserCDHash"

  /// Returns nil only for the exact browser build a paired release names.
  /// Otherwise returns the explanation the unverified-browser confirmation shows.
  static func unverifiedReason(appInfo: [String: Any], browserCDHash: String?) -> String? {
    let version = (appInfo["CFBundleShortVersionString"] as? String)
      .map { "Origin Trace " + $0 } ?? "This Origin Trace build"
    let limits =
      "Native capture features such as Wasm dispatch capture may be missing. "
      + "Native capture completeness is not established. Continue only if you accept these limits."
    let releaseType = appInfo[releaseTypeKey] as? String
    if releaseType == "companion" {
      return version + " is a companion-only release with no verified browser build. " + limits
    }
    if releaseType == "paired",
      let pinned = appInfo[pairedBrowserKey] as? String,
      isCodeDirectoryHash(pinned),
      browserCDHash == pinned
    {
      return nil
    }
    return version
      + " is verified only with the exact Brave Browser Development build published in the same release. "
      + "This browser could not be identified as that build. " + limits
  }

  /// Lowercase hexadecimal hash of the bundle's main code directory, as printed
  /// by `codesign -dvvv` (`CDHash=`), or nil when no signature can be read.
  static func codeDirectoryHash(applicationURL: URL) -> String? {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(applicationURL as CFURL, [], &code) == errSecSuccess,
      let code
    else {
      return nil
    }
    var information: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(), &information) == errSecSuccess,
      let values = information as? [String: Any],
      let unique = values[kSecCodeInfoUnique as String] as? Data,
      !unique.isEmpty
    else {
      return nil
    }
    return unique.map { String(format: "%02x", $0) }.joined()
  }

  private static func isCodeDirectoryHash(_ value: String) -> Bool {
    value.utf8.count == 40 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
}
