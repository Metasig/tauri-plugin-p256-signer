import Foundation
#if canImport(Tauri)
import Tauri
import SwiftRs
#endif

// Bridge result wrapper used to return an { ok, data, error } shape to the Tauri invoke resolver.
public struct BridgeResult<T: Encodable>: Encodable {
    public let ok: Bool
    public let data: T?
    public let error: String?
    public init(ok: Bool, data: T? = nil, error: String? = nil) {
        self.ok = ok
        self.data = data
        self.error = error
    }
}

#if canImport(Tauri)
@objc(P256SignerPlugin)
public class P256SignerPlugin: Plugin {
    private let core = P256SignerPluginCore()

    // Helper: try to decode args or reject the invoke with explanation.
    private func parseOrReject<T: Decodable>(_ type: T.Type, _ invoke: Invoke) -> T? {
        do {
            return try invoke.parseArgs(T.self)
        } catch {
            // Reject the invoke with a consistent message.
            invoke.reject("invalid_args: \(error)")
            return nil
        }
    }

    // MARK: - Commands (match Android names & arg shapes)

    // create_credential(params: CreateCredentialParams)
    @objc public func create_credential(_ invoke: Invoke) throws {
        // guard let params: CreateCredentialParams = parseOrReject(CreateCredentialParams.self, invoke) else { return }
        core.createCredential(params: params) { result in
            switch result {
            case .success(let cred):
                invoke.resolve(BridgeResult<CredentialResult>(ok: true, data: cred))
            case .failure(let err):
                invoke.resolve(BridgeResult<CredentialResult>(ok: false, data: nil, error: err.localizedDescription))
            }
        }
    }

    // get_credential(params: GetCredentialParams)
    @objc public func get_credential(_ invoke: Invoke) throws {
        // guard let params: GetCredentialParams = parseOrReject(GetCredentialParams.self, invoke) else { return }
        core.getCredential(params: params) { result in
            switch result {
            case .success(let assertion):
                invoke.resolve(BridgeResult<AssertionResult>(ok: true, data: assertion))
            case .failure(let err):
                invoke.resolve(BridgeResult<AssertionResult>(ok: false, data: nil, error: err.localizedDescription))
            }
        }
    }

    // sign(params: SignParams)
    @objc public func sign(_ invoke: Invoke) throws {
        // guard let params: SignParams = parseOrReject(SignParams.self, invoke) else { return }
        core.sign(params: params) { result in
            switch result {
            case .success(let assertion):
                invoke.resolve(BridgeResult<AssertionResult>(ok: true, data: assertion))
            case .failure(let err):
                invoke.resolve(BridgeResult<AssertionResult>(ok: false, data: nil, error: err.localizedDescription))
            }
        }
    }
}

@_cdecl("init_plugin_p256_signer")
@available(iOS 17, *)
func initPlugin() -> Plugin {
  return P256SignerPlugin()
}
#else
@_cdecl("init_plugin_p256_signer")
public func initPluginP256Signer() -> UnsafeMutableRawPointer? {
    return nil
}
#endif
