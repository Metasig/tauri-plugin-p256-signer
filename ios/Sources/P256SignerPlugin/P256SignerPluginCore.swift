import AuthenticationServices
import Foundation

public final class P256SignerPluginCore: NSObject {

    public override init() {
        super.init()
    }
    
        public func createCredential(
            params: CreateCredentialParams,
            completion: @escaping (Result<CredentialResult, Error>) -> Void
        ) {
            if #available(iOS 17.0, *) {
                do {
                    let challenge = try Base64URL.decode(params.challenge)
                    let userID = try Base64URL.decode(params.userId)
                    
                    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                        relyingPartyIdentifier: params.rpId)
                    let request = provider.createCredentialRegistrationRequest(
                        challenge: challenge,
                        name: params.userName,
                        userID: userID
                    )
                    if let displayName = params.userDisplayName {
                        request.displayName = displayName
                    }
                    
                    let controller = ASAuthorizationController(authorizationRequests: [request])
                    let delegate = RegistrationDelegate { result in
                        completion(result)
                    }
                    controller.delegate = delegate
                    controller.presentationContextProvider = nil
                    objc_setAssociatedObject(
                        controller, AssociationKey.delegateKey, delegate, .OBJC_ASSOCIATION_RETAIN_NONATOMIC
                    )
                    controller.performRequests()
                } catch {
                    completion(.failure(error))
                }
            }
        }


    public func getCredential(
        params: GetCredentialParams, completion: @escaping (Result<AssertionResult, Error>) -> Void
    ) {
        if #available(iOS 17.0, *) {
            do {
                let challenge = try Base64URL.decode(params.challenge)
                let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                    relyingPartyIdentifier: params.rpId)
                let request = provider.createCredentialAssertionRequest(challenge: challenge)
                
                let controller = ASAuthorizationController(authorizationRequests: [request])
                let delegate = AssertionDelegate { result in
                    completion(result)
                }
                controller.delegate = delegate
                controller.presentationContextProvider = nil
                objc_setAssociatedObject(
                    controller, AssociationKey.delegateKey, delegate, .OBJC_ASSOCIATION_RETAIN_NONATOMIC
                )
                controller.performRequests()
            } catch {
                completion(.failure(error))
            }
        }
    }

    public func sign(
        params: SignParams, completion: @escaping (Result<AssertionResult, Error>) -> Void
    ) {
        if #available(iOS 17.0, *) {
            do {
                let challenge = try Base64URL.decode(params.challenge)
                let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                    relyingPartyIdentifier: params.rpId)
                let request = provider.createCredentialAssertionRequest(challenge: challenge)
                if let allow = params.allowCredentialIds {
                    request.allowedCredentials = try allow.map {
                        let id = try Base64URL.decode($0)
                        return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
                    }
                }
                
                let controller = ASAuthorizationController(authorizationRequests: [request])
                let delegate = AssertionDelegate { result in
                    completion(result)
                }
                controller.delegate = delegate
                controller.presentationContextProvider = nil
                objc_setAssociatedObject(
                    controller, AssociationKey.delegateKey, delegate, .OBJC_ASSOCIATION_RETAIN_NONATOMIC
                )
                controller.performRequests()
            } catch {
                completion(.failure(error))
            }
        }
    }
}

private enum AssociationKey {
    static var delegateKey = "P256SignerPlugin_delegate_key"
}

private final class RegistrationDelegate: NSObject, ASAuthorizationControllerDelegate {
    private let completion: (Result<CredentialResult, Error>) -> Void

    init(completion: @escaping (Result<CredentialResult, Error>) -> Void) {
        self.completion = completion
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard
            let credential = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration
        else {
            completion(
                .failure(
                    NSError(
                        domain: "P256SignerPlugin", code: -2,
                        userInfo: [NSLocalizedDescriptionKey: "Unexpected credential type"])))
            return
        }
        let result = CredentialResult(
            id: Base64URL.encode(credential.credentialID),
            rawAttestationObject: Base64URL.encode(credential.rawAttestationObject!),
            clientDataJSON: Base64URL.encode(credential.rawClientDataJSON)
        )
        completion(.success(result))
    }

    func authorizationController(
        controller: ASAuthorizationController, didCompleteWithError error: Error
    ) {
        completion(.failure(error))
    }
}

private final class AssertionDelegate: NSObject, ASAuthorizationControllerDelegate {
    private let completion: (Result<AssertionResult, Error>) -> Void

    init(completion: @escaping (Result<AssertionResult, Error>) -> Void) {
        self.completion = completion
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard
            let assertion = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion
        else {
            completion(
                .failure(
                    NSError(
                        domain: "P256SignerPlugin", code: -2,
                        userInfo: [NSLocalizedDescriptionKey: "Unexpected credential type"])))
            return
        }
        let res = AssertionResult(
            id: Base64URL.encode(assertion.credentialID),
            authenticatorData: Base64URL.encode(assertion.rawAuthenticatorData),
            clientDataJSON: Base64URL.encode(assertion.rawClientDataJSON),
            signature: Base64URL.encode(assertion.signature),
            userHandle: assertion.userID.isEmpty ? nil : Base64URL.encode(assertion.userID)
        )
        completion(.success(res))
    }

    func authorizationController(
        controller: ASAuthorizationController, didCompleteWithError error: Error
    ) {
        completion(.failure(error))
    }
}
