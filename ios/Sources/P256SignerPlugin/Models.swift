
import Foundation

public struct CreateCredentialParams: Codable {
    public let rpId: String
    public let challenge: String          // base64url
    public let userId: String             // base64url
    public let userName: String
    public let userDisplayName: String?

    public init(rpId: String, challenge: String, userId: String, userName: String, userDisplayName: String? = nil) {
        self.rpId = rpId
        self.challenge = challenge
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
    }
}

public struct GetCredentialParams: Codable {
    public let rpId: String
    public let challenge: String          // base64url

    public init(rpId: String, challenge: String) {
        self.rpId = rpId
        self.challenge = challenge
    }
}

public struct SignParams: Codable {
    public let rpId: String
    public let challenge: String          // base64url
    public let allowCredentialIds: [String]? // base64url list

    public init(rpId: String, challenge: String, allowCredentialIds: [String]? = nil) {
        self.rpId = rpId
        self.challenge = challenge
        self.allowCredentialIds = allowCredentialIds
    }
}

public struct CredentialResult: Codable {
    public let id: String                 // base64url credential ID
    public let rawAttestationObject: String // base64url
    public let clientDataJSON: String     // base64url
}

public struct AssertionResult: Codable {
    public let id: String                 // base64url credential ID
    public let authenticatorData: String  // base64url
    public let clientDataJSON: String     // base64url
    public let signature: String          // base64url
    public let userHandle: String?        // base64url
}
