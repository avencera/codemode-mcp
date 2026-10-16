import CompanionCore
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import UIKit

/// The calls the Rust core leaves to the app: the Keychain, the Secure
/// Enclave and Face ID. The core calls them off the main thread and may wait
/// on them, so each one blocks until it is done
final class SystemPlatform: Platform, @unchecked Sendable {
    private static let service = "com.avencera.codemode-mcp.companion"
    /// The Keychain item holding the Secure Enclave key's opaque handle; the
    /// key itself never leaves the Secure Enclave
    private static let sealKeyItem = "seal-key"

    private let name: String
    private let lock = NSLock()
    /// The Face ID context of each read whose prompt is up, so the core can
    /// take it down
    private var contexts: [String: LAContext] = [:]
    /// Reads taken down before their prompt came up: the core cancels as
    /// soon as it asks, and the blocking call may not have started yet
    private var cancelled: Set<String> = []

    init() {
        name = MainActor.assumeIsolated { UIDevice.current.name }

        // Keychain items outlive an uninstall; a fresh install must not
        // answer for a pairing it no longer shows
        let launched = "launched"
        if !UserDefaults.standard.bool(forKey: launched) {
            SecItemDelete([
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: Self.service,
            ] as CFDictionary)
            UserDefaults.standard.set(true, forKey: launched)
        }
    }

    // MARK: Keychain

    func loadSecret(key: String) -> Data? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: key,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ] as CFDictionary, &result)

        return status == errSecSuccess ? result as? Data : nil
    }

    func saveSecret(key: String, value: Data) throws {
        deleteSecret(key: key)
        let status = SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: key,
            kSecValueData: value,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw PlatformError.Failed(message: "the Keychain refused \(key) (\(status))")
        }
    }

    func deleteSecret(key: String) {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: key,
        ] as CFDictionary)
    }

    // MARK: Secure Enclave

    func createSealKey() throws -> Data {
        deleteSealKey()
        var error: Unmanaged<CFError>?
        // usable only after Face ID, and only with the faces enrolled now
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw PlatformError.Failed(message: "cannot describe the key's access: \(String(describing: error))")
        }

        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            try saveSecret(key: Self.sealKeyItem, value: key.dataRepresentation)

            return key.publicKey.x963Representation
        } catch let error as PlatformError {
            throw error
        } catch {
            throw PlatformError.Failed(message: "the Secure Enclave refused a key: \(error.localizedDescription)")
        }
    }

    func deleteSealKey() {
        deleteSecret(key: Self.sealKeyItem)
    }

    // MARK: Face ID

    func openSealed(request: OpenRequest) throws -> String {
        guard let handle = loadSecret(key: Self.sealKeyItem) else {
            throw OpenError.Failed(message: "this iPhone has no seal key; pair it again")
        }

        let context = LAContext()
        context.localizedCancelTitle = "Deny"
        let alreadyCancelled = lock.withLock {
            contexts[request.id] = context
            return cancelled.remove(request.id) != nil
        }
        if alreadyCancelled {
            _ = lock.withLock { contexts.removeValue(forKey: request.id) }
            throw OpenError.Denied
        }
        defer { _ = lock.withLock { contexts.removeValue(forKey: request.id) } }

        // asked once here; the key use below takes this context instead of
        // prompting again
        let reason = "Read \(request.reference) for codemode-mcp on \(request.gatewayName)"
        let answered = DispatchSemaphore(value: 0)
        var refusal: Error?
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { approved, error in
            if !approved { refusal = error ?? LAError(.authenticationFailed) }
            answered.signal()
        }
        answered.wait()
        if let refusal {
            switch (refusal as? LAError)?.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback, .notInteractive:
                throw OpenError.Denied
            case .biometryLockout, .biometryNotEnrolled, .biometryNotAvailable:
                throw OpenError.Failed(message: "Face ID is unavailable: \(refusal.localizedDescription)")
            default:
                throw OpenError.Denied
            }
        }

        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: handle,
                authenticationContext: context
            )
            var recipient = try HPKE.Recipient(
                privateKey: key,
                ciphersuite: .P256_SHA256_AES_GCM_256,
                info: request.info,
                encapsulatedKey: request.enc
            )
            let plaintext = try recipient.open(request.ciphertext)
            guard let value = String(data: plaintext, encoding: .utf8) else {
                throw OpenError.Failed(message: "the value is not text")
            }

            return value
        } catch let error as OpenError {
            throw error
        } catch {
            // a changed Face ID enrollment voids the key; a new pairing makes another
            throw OpenError.Failed(message: "the value did not open: \(error.localizedDescription)")
        }
    }

    func cancelOpen(id: String) {
        let context = lock.withLock {
            if contexts[id] == nil { cancelled.insert(id) }
            return contexts[id]
        }
        context?.invalidate()
    }

    func deviceName() -> String {
        name
    }
}
