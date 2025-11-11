import SwiftRs
import Tauri
import UIKit
import WebKit
import AuthenticationServices
import LocalAuthentication

protocol PasskeyResultHandler {
    func onSuccess(_ data: Any)
    func onFailure(_ error: Error)
}

@available(iOS 15.0, *)
class PasskeyDelegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private let handler: PasskeyResultHandler
    var promise: Invoke?
    
    init(handler: PasskeyResultHandler) {
        self.handler = handler
        super.init()
    }
    
    // Perform the authorization request for a given ASAuthorizationController instance
    func performAuthForController(controller: ASAuthorizationController) {
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }
    
    // Provide window for authentication UI
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes
        let windowScene = scenes.first as? UIWindowScene
        guard let window = windowScene?.windows.first else {
            return ASPresentationAnchor()
        }
        return window
    }
    
    // CALLBACK FOR ASAuthorizationController
    // Handle authorization errors
    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        handler.onFailure(error)
    }
    
    // Handle successful authorization
    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        switch authorization.credential {
        case let credential as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            handlePlatformPublicKeyRegistrationResponse(credential: credential)
            
        case let credential as ASAuthorizationSecurityKeyPublicKeyCredentialRegistration:
            handleSecurityKeyPublicKeyRegistrationResponse(credential: credential)
            
        case let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            handlePlatformPublicKeyAssertionResponse(credential: credential)
            
        case let credential as ASAuthorizationSecurityKeyPublicKeyCredentialAssertion:
            handleSecurityKeyPublicKeyAssertionResponse(credential: credential)
            
        default:
            handler.onFailure(ASAuthorizationError(.invalidResponse))
        }
    }
    
    // Handle platform key registration
    private func handlePlatformPublicKeyRegistrationResponse(credential: ASAuthorizationPlatformPublicKeyCredentialRegistration) {
        guard let attestationObject = credential.rawAttestationObject else {
            handler.onFailure(ASAuthorizationError(.invalidResponse))
            return
        }

        // Extract public key
        let publicKey = getPublicKey(from: attestationObject)?.toBase64URLEncodedString()
        let authenticatorData = getAuthenticatorData(from: attestationObject)?.toBase64URLEncodedString()
        let publicKeyAlgorithm = getPublicKeyAlgorithm(from: attestationObject)

        // Create response with all required fields
        var response = AuthenticatorAttestationResponseJSON()
        response.clientDataJSON = credential.rawClientDataJSON.toBase64URLEncodedString()
        if let publicKey = publicKey {
          response.publicKey = publicKey
        }
        if let authenticatorData = authenticatorData {
          response.authenticatorData = authenticatorData
        }
        if let publicKeyAlgorithm = publicKeyAlgorithm {
          response.publicKeyAlgorithm = publicKeyAlgorithm
        }
        response.transports = ["internal"] // FIXME: Support Touch ID/Face ID only for now
        response.attestationObject = attestationObject.toBase64URLEncodedString()
        
        // Create the full registration response
        var registrationResponse = RegistrationResponseJSON()
        registrationResponse.id = credential.credentialID.toBase64URLEncodedString()
        registrationResponse.rawId = credential.credentialID.toBase64URLEncodedString()
        registrationResponse.response = response
        registrationResponse.authenticatorAttachment = "platform"
        registrationResponse.type = "public-key"
        
        handler.onSuccess(registrationResponse)
    }
    
    // Handle security key registration
    private func handleSecurityKeyPublicKeyRegistrationResponse(credential: ASAuthorizationSecurityKeyPublicKeyCredentialRegistration) {
        guard let attestationObject = credential.rawAttestationObject else {
            handler.onFailure(ASAuthorizationError(.invalidResponse))
            return
        }

        // Extract public key
        let publicKey = getPublicKey(from: attestationObject)?.toBase64URLEncodedString()
        let authenticatorData = getAuthenticatorData(from: attestationObject)?.toBase64URLEncodedString()
        let publicKeyAlgorithm = getPublicKeyAlgorithm(from: attestationObject)

        // Create response with all required fields
        var response = AuthenticatorAttestationResponseJSON()
        response.clientDataJSON = credential.rawClientDataJSON.toBase64URLEncodedString()
        if let publicKey = publicKey {
          response.publicKey = publicKey
        }
        if let authenticatorData = authenticatorData {
          response.authenticatorData = authenticatorData
        }
        if let publicKeyAlgorithm = publicKeyAlgorithm {
          response.publicKeyAlgorithm = publicKeyAlgorithm
        }
        response.transports = ["usb", "nfc", "ble"]
        response.attestationObject = attestationObject.toBase64URLEncodedString()
        
        // Create the full registration response
        var registrationResponse = RegistrationResponseJSON()
        registrationResponse.id = credential.credentialID.toBase64URLEncodedString()
        registrationResponse.rawId = credential.credentialID.toBase64URLEncodedString()
        registrationResponse.response = response
        registrationResponse.authenticatorAttachment = "cross-platform"
        registrationResponse.type = "public-key"
        
        handler.onSuccess(registrationResponse)
    }
    
    // Handle platform key authentication
    private func handlePlatformPublicKeyAssertionResponse(credential: ASAuthorizationPlatformPublicKeyCredentialAssertion) {
        guard let signature = credential.signature else {
            handler.onFailure(ASAuthorizationError(.invalidResponse))
            return
        }
        
        // Create the assertion response
        var response = AuthenticatorAssertionResponseJSON()
        response.authenticatorData = credential.rawAuthenticatorData.toBase64URLEncodedString()
        response.clientDataJSON = credential.rawClientDataJSON.toBase64URLEncodedString()
        response.signature = signature.toBase64URLEncodedString()
        if let userID = credential.userID {
            response.userHandle = userID.toBase64URLEncodedString()
        }
        
        // Create the full authentication response
        var authResponse = AuthenticationResponseJSON()
        authResponse.id = credential.credentialID.toBase64URLEncodedString()
        authResponse.rawId = credential.credentialID.toBase64URLEncodedString()
        authResponse.response = response
        authResponse.authenticatorAttachment = "platform"
        authResponse.type = "public-key"
        
        handler.onSuccess(authResponse)
    }
    
    // Handle security key authentication
    private func handleSecurityKeyPublicKeyAssertionResponse(credential: ASAuthorizationSecurityKeyPublicKeyCredentialAssertion) {
        guard let signature = credential.signature else {
            handler.onFailure(ASAuthorizationError(.invalidResponse))
            return
        }
        
        // Create the assertion response
        var response = AuthenticatorAssertionResponseJSON()
        response.authenticatorData = credential.rawAuthenticatorData.toBase64URLEncodedString()
        response.clientDataJSON = credential.rawClientDataJSON.toBase64URLEncodedString()
        response.signature = signature.toBase64URLEncodedString()
        if let userID = credential.userID {
            response.userHandle = userID.toBase64URLEncodedString()
        }
        
        // Create the full authentication response
        var authResponse = AuthenticationResponseJSON()
        authResponse.id = credential.credentialID.toBase64URLEncodedString()
        authResponse.rawId = credential.credentialID.toBase64URLEncodedString()
        authResponse.response = response
        authResponse.authenticatorAttachment = "cross-platform"
        authResponse.type = "public-key"
        
        handler.onSuccess(authResponse)
    }

    // Extract public key from attestation object
    private func getPublicKey(from attestationObject: Data) -> Data? {
      // Use the CBOR decoder to extract the public key
      return SimpleCBORDecoder.extractPublicKey(from: attestationObject)
    }

    // Extract authenticatorData from attestation object
    private func getAuthenticatorData(from attestationObject: Data) -> Data? {
      // Use the CBOR decoder to extract the authenticator data
      return SimpleCBORDecoder.extractAuthenticatorData(from: attestationObject)
    }

    // Extract authenticatorData from attestation object
    private func getPublicKeyAlgorithm(from attestationObject: Data) -> Int? {
      // Use the CBOR decoder to extract the authenticator data
      return SimpleCBORDecoder.extractPublicKeyAlgorithm(from: attestationObject)
    }


}
