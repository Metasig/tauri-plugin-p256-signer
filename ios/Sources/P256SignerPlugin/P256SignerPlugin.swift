import SwiftRs
import Tauri
import UIKit
import WebKit
import AuthenticationServices
import LocalAuthentication

class CreateCredentialRequestParams: Decodable {
    let creationParams: String?
}

class GetCredentialRequestParams: Decodable {
    let getParams: String?
}

enum P256SignerError: Error {
    case runtimeError(String)
}

class P256SignerPlugin: Plugin, PasskeyResultHandler {
    private var passkeyDelegate: PasskeyDelegate?
    
    @objc public func create_credential(_ invoke: Invoke) throws {
        do {
            // Decode message
            let args = try invoke.parseArgs(CreateCredentialRequestParams.self)
            let request = args.creationParams
            
            // Check iOS version
            if #unavailable(iOS 15.0) {
                invoke.reject("NotSupportedException")
                return
            }
            
            // Validate input - Yes, it receive request json as string
            guard let requestJson = request as? String else {
                invoke.reject("InvalidChallengeException")
                return
            }
            
            // Check if there's already an operation in progress
            if self.passkeyDelegate != nil {
                invoke.reject("PendingPasskeyRequestException")
                return
            }
            
            // Check biometric availability
            let context = LAContext()
            if context.biometricType == .none {
                invoke.reject("BiometricException")
                return
            }
            
            // Create delegate to handle auth callbacks - BIG CHUNK OF WORK HERE
            let delegate = PasskeyDelegate(handler: self)
            self.passkeyDelegate = delegate
            delegate.promise = invoke
            
            // Create registration requests
            try self.handleCreatePasskey(requestJson: requestJson, delegate: delegate, promise: invoke)
        } catch {
            invoke.reject("\(error)")
        }
    }
    
    @objc public func get_credential(_ invoke: Invoke) throws {
        do {
            // Decode message
            let args = try invoke.parseArgs(GetCredentialRequestParams.self)
            let request = args.getParams
            
            // CreatePublicKeyCredentialRequest from webauth json string
            
            // Check iOS version
            if #unavailable(iOS 15.0) {
                invoke.reject("NotSupportedException")
                return
            }
            
            // Validate input
            guard let requestJson = request as? String else {
                invoke.reject("InvalidChallengeException")
                return
            }
            
            // Check if there's already an operation in progress
            if self.passkeyDelegate != nil {
                invoke.reject("PendingPasskeyRequestException")
                return
            }
            
            // Check biometric availability
            let context = LAContext()
            if context.biometricType == .none {
                invoke.reject("BiometricException")
                return
            }
            
            // Create delegate to handle auth callbacks
            let delegate = PasskeyDelegate(handler: self)
            self.passkeyDelegate = delegate
            delegate.promise = invoke
            
            // Create authentication requests
            try self.handleAuthenticatePasskey(requestJson: requestJson, delegate: delegate, promise: invoke)
        } catch {
            invoke.reject("\(error)")
        }
    }
    
    @available(iOS 15.0, *)
    private func handleCreatePasskey(requestJson: String, delegate: PasskeyDelegate, promise: Invoke) throws {
        guard let requestData: Data = requestJson.data(using: .utf8) else {
            throw P256SignerError.runtimeError("InvalidChallengeException")
        }
        
        // Parse request json
        let options = try JSONDecoder().decode(PublicKeyCredentialCreationOptions.self, from: requestData)
        
        // Get challenge and user data
        guard let challenge = Data(base64URLEncoded: options.challenge) else {
            throw P256SignerError.runtimeError("InvalidChallengeException")
        }
        
        guard let userId = Data(base64URLEncoded: options.user.id) else {
            throw P256SignerError.runtimeError("InvalidUserIdException")
        }
        
        // Set up requests based on authenticator attachment preference
        var requests = [ASAuthorizationRequest]()
        
        // Create platform request if requested or if no specific authenticator is specified
        if options.authenticatorSelection?.authenticatorAttachment != "cross-platform" {
            let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rp.id)
            let platformRequest = platformProvider.createCredentialRegistrationRequest(
                challenge: challenge,
                name: options.user.name,
                userID: userId
            )
            
            if let userVerification = options.authenticatorSelection?.userVerification {
                platformRequest.userVerificationPreference = convertUserVerificationPreference(userVerification)
            }
            
            requests.append(platformRequest)
        }
        
        // Create security key request if requested or if no specific authenticator is specified
        if options.authenticatorSelection?.authenticatorAttachment == "cross-platform" || options.authenticatorSelection?.authenticatorAttachment == nil {
            let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: options.rp.id)
            let securityKeyRequest = securityKeyProvider.createCredentialRegistrationRequest(
                challenge: challenge,
                displayName: options.user.displayName,
                name: options.user.name,
                userID: userId
            )
            
            // Configure security key options
            if let algParams = options.pubKeyCredParams {
                securityKeyRequest.credentialParameters = algParams.map { param in
                    return ASAuthorizationPublicKeyCredentialParameters(algorithm: ASCOSEAlgorithmIdentifier(rawValue: param.alg))
                }
            }
            
            if let userVerification = options.authenticatorSelection?.userVerification {
                securityKeyRequest.userVerificationPreference = convertUserVerificationPreference(userVerification)
            }
            
            if let attestation = options.attestation {
                securityKeyRequest.attestationPreference = convertAttestationPreference(attestation)
            }
            
            if let residentKey = options.authenticatorSelection?.residentKey {
                securityKeyRequest.residentKeyPreference = convertResidentKeyPreference(residentKey)
            }
            
            requests.append(securityKeyRequest)
        }
        
        // Check if we have any valid requests
        if requests.isEmpty {
            throw P256SignerError.runtimeError("PasskeyRequestFailedException")
        }
        
        // Create auth controller and perform requests
        let authController = ASAuthorizationController(authorizationRequests: requests)
        delegate.performAuthForController(controller: authController)
    }
    
    @available(iOS 15.0, *)
    private func handleAuthenticatePasskey(requestJson: String, delegate: PasskeyDelegate, promise: Invoke) throws {
        guard let requestData = requestJson.data(using: .utf8) else {
            throw P256SignerError.runtimeError("InvalidChallengeException")
        }
        
        // Parse request
        let options = try JSONDecoder().decode(PublicKeyCredentialRequestOptions.self, from: requestData)
        
        // Get challenge
        guard let challenge = Data(base64URLEncoded: options.challenge) else {
            throw P256SignerError.runtimeError("InvalidChallengeException")
            return
        }
        
        var requests = [ASAuthorizationRequest]()
        
        // Create platform request
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
        let platformRequest = platformProvider.createCredentialAssertionRequest(challenge: challenge) // Yes, decoded above
        
        // Configure platform request
        //  it actually triggers the local authentication in the means of Touch ID, Face ID, or PIN/password to unlock your Keychain and access the passkey to generate a signature
        if let userVerification = options.userVerification { // match
            platformRequest.userVerificationPreference = convertUserVerificationPreference(userVerification)
        }
        
        if let allowCredentials = options.allowCredentials, !allowCredentials.isEmpty {
            platformRequest.allowedCredentials = allowCredentials.compactMap { credential in
                guard let credentialData = Data(base64URLEncoded: credential.id) else {
                    return nil
                }
                return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialData)
            }
        }
        
        requests.append(platformRequest)
        
        // Create security key request
        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
        let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: challenge)
        
        // Configure security key request
        if let userVerification = options.userVerification {
            securityKeyRequest.userVerificationPreference = convertUserVerificationPreference(userVerification)
        }
        
        if let allowCredentials = options.allowCredentials, !allowCredentials.isEmpty {
            securityKeyRequest.allowedCredentials = allowCredentials.compactMap { credential in
                guard let credentialData = Data(base64URLEncoded: credential.id) else {
                    return nil
                }
                
                var transports = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                if let credentialTransports = credential.transports, !credentialTransports.isEmpty {
                    transports = credentialTransports.compactMap { transport -> ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport? in
                        switch transport {
                        case "ble": return .bluetooth
                        case "nfc": return .nfc
                        case "usb": return .usb
                        default: return nil
                        }
                    }
                }
                
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: credentialData,
                    transports: transports
                )
            }
        }
        
        requests.append(securityKeyRequest)
        
        // Create auth controller and perform requests
        // authController need delegate and presentationContextProvider
        let authController = ASAuthorizationController(authorizationRequests: requests)
        delegate.performAuthForController(controller: authController)
    }
    
    // MARK: - PasskeyResultHandler
    
    public func onSuccess(_ data: Any) {
        guard let delegate = passkeyDelegate else {
            return
        }
        
        // Reset the delegate to allow future operations
        passkeyDelegate = nil
        
        do {
            // Convert JSON to dictionary and then to JSON **string**
            let json: [String: Any]
            
            if let registrationData = data as? RegistrationResponseJSON {
                // Manually create dictionary representation
                var responseDict: [String: Any] = [
                    "type": registrationData.type
                ]
                
                if let attachment = registrationData.authenticatorAttachment {
                    responseDict["authenticatorAttachment"] = attachment
                }
                
                responseDict["id"] = registrationData.id
                responseDict["rawId"] = registrationData.rawId
                
                // Create response dictionary
                var responseObjDict: [String: Any] = [:]
                
                if let authenticatorData = registrationData.response?.authenticatorData {
                    responseObjDict["authenticatorData"] = authenticatorData
                }
                if let clientDataJSON = registrationData.response?.clientDataJSON {
                    responseObjDict["clientDataJSON"] = clientDataJSON
                }
                
                if let attestationObject = registrationData.response?.attestationObject {
                    responseObjDict["attestationObject"] = attestationObject
                }
                
                if let publicKey = registrationData.response?.publicKey {
                    responseObjDict["publicKey"] = publicKey
                }
                
                if let publicKeyAlg = registrationData.response?.publicKeyAlgorithm {
                    responseObjDict["publicKeyAlgorithm"] = publicKeyAlg
                }
                
                if let transports = registrationData.response?.transports {
                    responseObjDict["transports"] = transports
                }
                
                responseDict["response"] = responseObjDict
                
                json = responseDict
            } else if let authData = data as? AuthenticationResponseJSON {
                // Manually create dictionary representation
                var responseDict: [String: Any] = [
                    "type": authData.type
                ]
                
                if let attachment = authData.authenticatorAttachment {
                    responseDict["authenticatorAttachment"] = attachment
                }
                
                responseDict["id"] = authData.id
                responseDict["rawId"] = authData.rawId
                
                // Create response dictionary
                var responseObjDict: [String: Any] = [:]
                
                if let authenticatorData = authData.response?.authenticatorData {
                    responseObjDict["authenticatorData"] = authenticatorData
                }
                
                if let clientDataJSON = authData.response?.clientDataJSON {
                    responseObjDict["clientDataJSON"] = clientDataJSON
                }
                
                if let signature = authData.response?.signature {
                    responseObjDict["signature"] = signature
                }
                
                if let userHandle = authData.response?.userHandle {
                    responseObjDict["userHandle"] = userHandle
                }
                
                responseDict["response"] = responseObjDict
                
                json = responseDict
            } else {
                throw P256SignerError.runtimeError("UnknownException")
            }
            
            // Convert dictionary to JSON
            let jsonData = try JSONSerialization.data(withJSONObject: json, options: [])
            
            if let jsonString = String(data: jsonData, encoding: .utf8) {
                delegate.promise?.resolve(["pubKeyJson": jsonString])
            } else {
                throw P256SignerError.runtimeError("UnknownException")
            }
        } catch {
            print("Error serializing passkey response: \(error)")
            delegate.promise?.reject("UnknownException")
        }
    }
    
    public func onFailure(_ error: Error) {
        guard let delegate = passkeyDelegate else {
            return
        }
        
        // Reset the delegate to allow future operations
        passkeyDelegate = nil
        
        // Convert the error to an appropriate exception
        if let asError = error as? ASAuthorizationError {
            switch asError.code {
            case .canceled:
                delegate.promise?.reject("UserCancelledException")
            case .failed:
                // Get detailed error information
                let errorMessage = asError.localizedDescription
                let errorCode = asError.code.rawValue
                let underlyingError = asError.userInfo[NSUnderlyingErrorKey] as? Error
                
                // Create detailed error message
                var details = "ASAuthorizationError-PasskeyRequestFailedException"
                details += " | Code: \(errorCode)"
                details += " | Message: \(errorMessage)"
                
                if let underlying = underlyingError {
                    details += " | Underlying: \(underlying.localizedDescription)"
                }
                
                // Log for debugging
                print("Full error info: \(asError)")
                print("UserInfo: \(asError.userInfo)")
                
                delegate.promise?.reject(details)
            case .invalidResponse:
                delegate.promise?.reject("PasskeyAuthorizationFailedException")
            default:
                delegate.promise?.reject("UnknownException")
            }
        } else {
            delegate.promise?.reject("UnknownException")
        }
    }
    
    // MARK: - Helper Methods
    
    @available(iOS 15.0, *)
    private func convertUserVerificationPreference(_ value: String) -> ASAuthorizationPublicKeyCredentialUserVerificationPreference {
        switch value {
        case "required":
            return .required
        case "preferred":
            return .preferred
        case "discouraged":
            return .discouraged
        default:
            return .preferred
        }
    }
    
    @available(iOS 15.0, *)
    private func convertResidentKeyPreference(_ value: String) -> ASAuthorizationPublicKeyCredentialResidentKeyPreference {
        switch value {
        case "required":
            return .required
        case "preferred":
            return .preferred
        case "discouraged":
            return .discouraged
        default:
            return .preferred
        }
    }
    
    @available(iOS 15.0, *)
    private func convertAttestationPreference(_ value: String) -> ASAuthorizationPublicKeyCredentialAttestationKind {
        switch value {
        case "direct":
            return .direct
        case "indirect":
            return .indirect
        case "none":
            return .none
        case "enterprise":
            return .enterprise
        default:
            return .none
        }
    }
}

// Extension for biometric type checking
extension LAContext {
    enum BiometricType: String {
        case none
        case touchID
        case faceID
        case opticID
    }
    
    var biometricType: BiometricType {
        var error: NSError?
        
        guard self.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        if #available(iOS 11.0, *) {
            switch self.biometryType {
            case .none:
                return .none
            case .touchID:
                return .touchID
            case .faceID:
                return .faceID
            case .opticID:
                if #available(iOS 17.0, *) {
                    return .opticID
                } else {
                    return .none
                }
            @unknown default:
                return .none
            }
        }
        
        return self.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) ? .touchID : .none
    }
}

@_cdecl("init_plugin_p256_signer") func initPlugin() -> Plugin {
    return P256SignerPlugin()
}
