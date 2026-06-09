---
name: owasp-mobile
description: Apply OWASP Mobile Top 10:2024 security standards when writing or reviewing iOS, Android, React Native, Flutter, or cross-platform mobile application code. Covers insecure data storage, improper credential usage, insecure communication, privacy controls, and binary protections.
when_to_use: Use when building or reviewing iOS (Swift/Objective-C), Android (Kotlin/Java), React Native, Flutter/Dart, or cross-platform mobile apps. Also use for mobile API clients, deep link handling, push notification security, certificate pinning, biometric auth, or local data encryption.
---

# OWASP Mobile Top 10:2024

## Quick Reference

| # | Risk | Key Mitigation |
|---|------|----------------|
| M1 | Improper Credential Usage | Never hardcode credentials; use Keychain/Keystore; rotate secrets |
| M2 | Inadequate Supply Chain Security | Verify dependency integrity; audit third-party SDKs |
| M3 | Insecure Authentication/Authorization | Strong auth flows; validate server-side; no client-side auth bypass |
| M4 | Insufficient Input/Output Validation | Validate all input; sanitize before rendering; safe deep link handling |
| M5 | Insecure Communication | Certificate pinning; enforce TLS 1.2+; no cleartext traffic |
| M6 | Inadequate Privacy Controls | Minimize data collection; mask PII in logs/UI; respect permissions |
| M7 | Insufficient Binary Protections | Enable compiler protections; obfuscate; detect root/jailbreak |
| M8 | Security Misconfiguration | Remove debug flags; restrict exported components; lock permissions |
| M9 | Insecure Data Storage | Encrypt at rest; use platform secure storage; clear sensitive data |
| M10 | Insufficient Cryptography | Use platform crypto APIs; no custom crypto; proper key management |

---

## Mobile Security Checklist

### Credential & Secret Handling (M1)
- [ ] No hardcoded API keys, tokens, or passwords in source or compiled binary
- [ ] Credentials stored in Keychain (iOS) or Keystore (Android), not SharedPreferences
- [ ] OAuth tokens use short expiry and refresh rotation
- [ ] Biometric auth tied to a Keychain/Keystore key, not a boolean flag
- [ ] Certificate pinning implemented for all sensitive API endpoints

### Secure Communication (M5)
```swift
// iOS: enforce App Transport Security (Info.plist)
// UNSAFE — disables TLS requirement
<key>NSAllowsArbitraryLoads</key><true/>

// SAFE — explicit domain exceptions only
<key>NSExceptionDomains</key>
<dict>
  <key>api.example.com</key>
  <dict>
    <key>NSExceptionMinimumTLSVersion</key>
    <string>TLSv1.2</string>
  </dict>
</dict>
```

```kotlin
// Android: network_security_config.xml
// UNSAFE — allows cleartext
<base-config cleartextTrafficPermitted="true" />

// SAFE — deny cleartext, enforce TLS
<base-config cleartextTrafficPermitted="false">
  <trust-anchors>
    <certificates src="system" />
  </trust-anchors>
</base-config>
```

### Certificate Pinning
```swift
// iOS (URLSession)
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard let serverCert = challenge.protectionSpace.serverTrust,
          let pinnedHash = Bundle.main.pinnedCertHash,
          certHash(serverCert) == pinnedHash else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    completionHandler(.useCredential, URLCredential(trust: serverCert))
}
```

```kotlin
// Android (OkHttp)
val client = OkHttpClient.Builder()
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()
    ).build()
```

### Insecure Data Storage (M9)
```swift
// iOS — UNSAFE: storing sensitive data in UserDefaults
UserDefaults.standard.set(authToken, forKey: "auth_token")

// SAFE: use Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: authToken.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

```kotlin
// Android — UNSAFE: plaintext SharedPreferences
getSharedPreferences("app", MODE_PRIVATE).edit().putString("token", token).apply()

// SAFE: EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
).edit().putString("token", token).apply()
```

```dart
// Flutter — UNSAFE: SharedPreferences for secrets
SharedPreferences.getInstance().then((p) => p.setString('token', token));

// SAFE: flutter_secure_storage
const storage = FlutterSecureStorage();
await storage.write(key: 'token', value: token);
```

### Privacy Controls (M6)
- [ ] Camera/microphone/location permission requested just-in-time, not at startup
- [ ] No PII logged — scrub tokens, emails, names from crash reporters and analytics
- [ ] Screen content masked when app enters background (prevent screenshot in app switcher)
- [ ] Clipboard cleared after sensitive paste operations
- [ ] Analytics SDKs configured to exclude personal data

```swift
// iOS: mask screen on background
func applicationDidEnterBackground(_ application: UIApplication) {
    let blurView = UIVisualEffectView(effect: UIBlurEffect(style: .regular))
    blurView.frame = window?.bounds ?? .zero
    blurView.tag = 999
    window?.addSubview(blurView)
}
func applicationWillEnterForeground(_ application: UIApplication) {
    window?.viewWithTag(999)?.removeFromSuperview()
}
```

### Insufficient Input Validation & Deep Links (M4)
```swift
// UNSAFE — deep link passes user-controlled data directly to web view
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    let dest = url.queryParameters["redirect"] ?? ""
    webView.load(URLRequest(url: URL(string: dest)!))
    return true
}

// SAFE — allowlist destinations
let allowedHosts = ["example.com", "app.example.com"]
guard let dest = url.queryParameters["redirect"],
      let destURL = URL(string: dest),
      allowedHosts.contains(destURL.host ?? "") else { return false }
webView.load(URLRequest(url: destURL))
```

### Binary Protections (M7)

**iOS checklist:**
- [ ] Stack canaries enabled (default with Xcode, verify in build settings)
- [ ] ARC enabled (automatic reference counting)
- [ ] Position-independent executable (PIE) enabled
- [ ] Bitcode disabled in release (reduces attack surface)
- [ ] Jailbreak detection implemented for high-security apps

```swift
// Basic jailbreak detection (layer of defense, not foolproof)
func isJailbroken() -> Bool {
    let paths = ["/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd", "/etc/apt"]
    return paths.contains(where: { FileManager.default.fileExists(atPath: $0) })
}
```

**Android checklist:**
- [ ] `android:debuggable="false"` in release manifest
- [ ] ProGuard/R8 obfuscation enabled in release builds
- [ ] SafetyNet/Play Integrity API used for root detection on critical operations
- [ ] Exported components (`activity`, `service`, `receiver`) audited — unexported if not needed

```xml
<!-- UNSAFE: component exported by default or explicitly -->
<activity android:name=".AdminActivity" android:exported="true" />

<!-- SAFE: restrict to same app or known packages -->
<activity android:name=".AdminActivity" android:exported="false" />
```

### Security Misconfiguration (M8)
```xml
<!-- Android Manifest audit -->
<!-- Remove: android:allowBackup="true" — enables adb backup of app data -->
<application android:allowBackup="false" ...>

<!-- Remove: android:usesCleartextTraffic="true" -->
<!-- Ensure: android:debuggable="false" in release -->
```

### Insufficient Cryptography (M10)
```swift
// UNSAFE: custom/weak crypto
let key = "password123".data(using: .utf8)!
let encrypted = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), ...)

// SAFE: CryptoKit with AES-GCM
import CryptoKit
let key = SymmetricKey(size: .bits256)
let sealedBox = try AES.GCM.seal(plaintext, using: key)
```

```kotlin
// SAFE: Android Keystore + AES-GCM
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(KeyGenParameterSpec.Builder("my_key",
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build())
val secretKey = keyGen.generateKey()
```

---

## React Native Security Notes

- [ ] `AsyncStorage` is unencrypted — use `react-native-encrypted-storage` for secrets
- [ ] Hermes engine debugger disabled in production builds
- [ ] JavaScript bundle not extractable from APK (enable Hermes bytecode)
- [ ] Deep link scheme validated — use Universal Links (iOS) / App Links (Android) over custom schemes
- [ ] `WebView` with `javaScriptEnabled={true}` + `onShouldStartLoadWithRequest` to validate URLs

---

## Supply Chain (M2)

- [ ] Native SDKs reviewed for excessive permissions
- [ ] Third-party analytics/ad SDKs audited for data exfiltration
- [ ] Dependency lockfiles committed and integrity verified
- [ ] `pod audit` / `gradle dependencyCheckAnalyze` run in CI
- [ ] SDKs sourced from official registries only (CocoaPods, Maven Central, pub.dev)
