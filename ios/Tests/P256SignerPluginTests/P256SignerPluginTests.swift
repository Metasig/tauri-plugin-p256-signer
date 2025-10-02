
import XCTest
import AuthenticationServices
@testable import P256SignerPlugin

class CreateCredentialTests: XCTestCase {
    
    var webAuthnService: P256SignerPluginCore! // Replace with your actual service class name
    
    override func setUp() {
        super.setUp()
        webAuthnService = P256SignerPluginCore() // Replace with your actual service initialization
    }
    
    override func tearDown() {
        webAuthnService = nil
        super.tearDown()
    }
    
    // MARK: - Success Tests
    
    func testCreateCredential_WithValidParameters_ShouldSucceed() {
        // Given
        let expectation = XCTestExpectation(description: "Create credential should succeed")
        let validChallenge = "SGVsbG8gV29ybGQ" // Base64URL encoded "Hello World"
        let validUserId = "dXNlcklk" // Base64URL encoded "userId"
        let validParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: validChallenge,
            userId: validUserId,
            userName: "testuser@example.com",
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: validParams) { result in
            // Then
            switch result {
            case .success(let credentialResult):
                XCTAssertNotNil(credentialResult.id, "Credential ID should not be nil")
                XCTAssertFalse(credentialResult.id.isEmpty, "Credential ID should not be empty")
                XCTAssertNotNil(credentialResult.rawAttestationObject, "Raw attestation object should not be nil")
                XCTAssertFalse(credentialResult.rawAttestationObject.isEmpty, "Raw attestation object should not be empty")
                XCTAssertNotNil(credentialResult.clientDataJSON, "Client data JSON should not be nil")
                XCTAssertFalse(credentialResult.clientDataJSON.isEmpty, "Client data JSON should not be empty")
                
                // Verify that the client data contains our challenge
                do {
                    let clientDataData = try Base64URL.decode(credentialResult.clientDataJSON)
                    if let clientDataString = String(data: clientDataData, encoding: .utf8) {
                        XCTAssertTrue(clientDataString.contains(validChallenge) ||
                                     clientDataString.contains("SGVsbG8gV29ybGQ"),
                                     "Client data should contain the provided challenge")
                    }
                } catch {
                    XCTFail("Failed to decode client data JSON: \(error)")
                }
                
            case .failure(let error):
                XCTFail("Expected success, but got error: \(error)")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 30.0) // WebAuthn operations can take time
    }
    
    func testCreateCredential_WithOptionalDisplayName_ShouldSucceed() {
        // Given
        let expectation = XCTestExpectation(description: "Create credential without display name should succeed")
        let validParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: "SGVsbG8gV29ybGQ",
            userId: "dXNlcklk",
            userName: "testuser@example.com",
            userDisplayName: nil // Optional parameter not provided
        )
        
        // When
        webAuthnService.createCredential(params: validParams) { result in
            // Then
            switch result {
            case .success(let credentialResult):
                XCTAssertNotNil(credentialResult.id)
                XCTAssertNotNil(credentialResult.rawAttestationObject)
                XCTAssertNotNil(credentialResult.clientDataJSON)
            case .failure(let error):
                XCTFail("Expected success, but got error: \(error)")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 30.0)
    }
    
    // MARK: - Parameter Validation Tests
    
    func testCreateCredential_WithInvalidChallenge_ShouldFail() {
        // Given
        let expectation = XCTestExpectation(description: "Invalid challenge should fail")
        let invalidParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: "Invalid!Base64URL@#$", // Invalid Base64URL
            userId: "dXNlcklk",
            userName: "testuser@example.com",
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: invalidParams) { result in
            // Then
            switch result {
            case .success:
                XCTFail("Expected failure due to invalid challenge, but got success")
            case .failure(let error):
                XCTAssertNotNil(error, "Should return an error for invalid challenge")
                // Verify it's a Base64URL decoding error
                let errorDescription = error.localizedDescription.lowercased()
                XCTAssertTrue(errorDescription.contains("base64") ||
                             errorDescription.contains("decode") ||
                             errorDescription.contains("invalid"),
                             "Error should be related to Base64URL decoding: \(error)")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testCreateCredential_WithInvalidUserId_ShouldFail() {
        // Given
        let expectation = XCTestExpectation(description: "Invalid user ID should fail")
        let invalidParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: "SGVsbG8gV29ybGQ",
            userId: "Invalid!Base64URL@#$", // Invalid Base64URL
            userName: "testuser@example.com",
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: invalidParams) { result in
            // Then
            switch result {
            case .success:
                XCTFail("Expected failure due to invalid user ID, but got success")
            case .failure(let error):
                XCTAssertNotNil(error, "Should return an error for invalid user ID")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testCreateCredential_WithEmptyChallenge_ShouldFail() {
        // Given
        let expectation = XCTestExpectation(description: "Empty challenge should fail")
        let invalidParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: "", // Empty challenge
            userId: "dXNlcklk",
            userName: "testuser@example.com",
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: invalidParams) { result in
            // Then
            switch result {
            case .success:
                XCTFail("Expected failure due to empty challenge, but got success")
            case .failure(let error):
                XCTAssertNotNil(error, "Should return an error for empty challenge")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testCreateCredential_WithEmptyUserId_ShouldFail() {
        // Given
        let expectation = XCTestExpectation(description: "Empty user ID should fail")
        let invalidParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: "SGVsbG8gV29ybGQ",
            userId: "", // Empty user ID
            userName: "testuser@example.com",
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: invalidParams) { result in
            // Then
            switch result {
            case .success:
                XCTFail("Expected failure due to empty user ID, but got success")
            case .failure(let error):
                XCTAssertNotNil(error, "Should return an error for empty user ID")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testCreateCredential_WithEmptyUserName_ShouldFail() {
        // Given
        let expectation = XCTestExpectation(description: "Empty userName should fail")
        let invalidParams = CreateCredentialParams(
            rpId: "example.com",
            challenge: "SGVsbG8gV29ybGQ",
            userId: "dXNlcklk",
            userName: "", // Empty userName
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: invalidParams) { result in
            // Then
            switch result {
            case .success:
                XCTFail("Expected failure due to empty userName, but got success")
            case .failure(let error):
                XCTAssertNotNil(error, "Should return an error for empty userName")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testCreateCredential_WithEmptyRpId_ShouldFail() {
        // Given
        let expectation = XCTestExpectation(description: "Empty rpId should fail")
        let invalidParams = CreateCredentialParams(
            rpId: "", // Empty rpId
            challenge: "SGVsbG8gV29ybGQ",
            userId: "dXNlcklk",
            userName: "testuser@example.com",
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: invalidParams) { result in
            // Then
            switch result {
            case .success:
                XCTFail("Expected failure due to empty rpId, but got success")
            case .failure(let error):
                XCTAssertNotNil(error, "Should return an error for empty rpId")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    // MARK: - Edge Cases
    
    func testCreateCredential_WithVeryLongUserName_ShouldHandleGracefully() {
        // Given
        let expectation = XCTestExpectation(description: "Very long userName should be handled gracefully")
        let longUserName = String(repeating: "a", count: 1000) + "@example.com"
        let params = CreateCredentialParams(
            rpId: "example.com",
            challenge: "SGVsbG8gV29ybGQ",
            userId: "dXNlcklk",
            userName: longUserName,
            userDisplayName: "Test User"
        )
        
        // When
        webAuthnService.createCredential(params: params) { result in
            // Then
            // Either succeeds or fails gracefully (no crash)
            switch result {
            case .success(let credentialResult):
                XCTAssertNotNil(credentialResult.id)
            case .failure(let error):
                XCTAssertNotNil(error, "Should handle long userName gracefully")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 30.0)
    }
    
    func testCreateCredential_WithSpecialCharactersInUserName_ShouldHandleCorrectly() {
        // Given
        let expectation = XCTestExpectation(description: "Special characters in userName should be handled")
        let specialUserName = "test+user@example.com"
        let params = CreateCredentialParams(
            rpId: "example.com",
            challenge: "SGVsbG8gV29ybGQ",
            userId: "dXNlcklk",
            userName: specialUserName,
            userDisplayName: "Test User 🔐"
        )
        
        // When
        webAuthnService.createCredential(params: params) { result in
            // Then
            switch result {
            case .success(let credentialResult):
                XCTAssertNotNil(credentialResult.id)
                XCTAssertNotNil(credentialResult.rawAttestationObject)
                XCTAssertNotNil(credentialResult.clientDataJSON)
            case .failure(let error):
                XCTFail("Should handle special characters in userName: \(error)")
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 30.0)
    }
}

// Note: Uses Base64URL helper from Base64URL.swift

final class P256SignerPluginTests: XCTestCase {
    func testBase64URLRoundtrip() throws {
        let bytes = Data([0,1,2,3,250,251,252,253,254,255])
        let s = Base64URL.encode(bytes)
        let decoded = try Base64URL.decode(s)
        XCTAssertEqual(decoded, bytes)
        XCTAssertFalse(s.contains("+"))
        XCTAssertFalse(s.contains("/"))
        XCTAssertFalse(s.contains("="))
    }

    func testBridgeEncodesErrors() {
        let bridge = P256SignerPluginBridge()
        // Missing fields -> decode error -> ok:false JSON
        let expectation = XCTestExpectation(description: "error json")
        bridge.createCredential(json: "{}") { json in
            XCTAssertTrue(json.contains("\"ok\":false"))
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
    }
}

