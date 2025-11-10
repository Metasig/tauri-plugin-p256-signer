import {invoke} from "@tauri-apps/api/core";

// Serialize WebAuthn credential for JSON transmission
// Convert ArrayBuffer properties to base64Url-encoded strings
interface SerializedPublicKeyCredentialRequestOptions {
    allowCredentials?: Array<{
        id: string; // Base64URL encoded
        type: string;
        transports?: string[];
    }>;
    challenge: string; // Base64URL encoded
    extensions?: Record<string, any>;
    rpId?: string;
    timeout?: number;
    userVerification?: string;
}

function serializeWebAuthnCredential(credentialRequest: PublicKeyCredentialCreationOptions): PublicKeyCredentialCreationOptionsJSON {
    // Create a deep copy to avoid modifying the original object
    const serialized: PublicKeyCredentialCreationOptionsJSON = {
        challenge: bufferToBase64Url(credentialRequest.challenge as ArrayBuffer),
        rp: {
            ...credentialRequest.rp
        },
        user: {
            id: bufferToBase64Url(credentialRequest.user.id as ArrayBuffer),
            name: credentialRequest.user.name,
            displayName: credentialRequest.user.displayName
        },
        pubKeyCredParams: credentialRequest.pubKeyCredParams.map((param: { type: any; alg: any; }) => ({
            type: param.type,
            alg: param.alg
        }))
    };

    // Add optional properties if they exist
    if (credentialRequest.timeout !== undefined) {
        serialized.timeout = credentialRequest.timeout;
    }

    if (credentialRequest.authenticatorSelection) {
        serialized.authenticatorSelection = {
            ...credentialRequest.authenticatorSelection
        };
    }

    if (credentialRequest.attestation) {
        serialized.attestation = credentialRequest.attestation;
    }

    if (credentialRequest.extensions) {
        serialized.extensions = serializeExtensions(credentialRequest.extensions);
    }

    return serialized;
}

function serializeExtensions(extensions: AuthenticationExtensionsClientInputs): AuthenticationExtensionsClientInputsJSON {
    const serialized: any = {};
    
    if (extensions.largeBlob) {
        serialized.largeBlob = {
            ...extensions.largeBlob,
            write: extensions.largeBlob.write ? bufferToBase64Url(extensions.largeBlob.write as ArrayBuffer) : undefined
        };
    }
    
    // Copy other extension properties as-is
    for (const [key, value] of Object.entries(extensions)) {
        if (key !== 'largeBlob') {
            serialized[key] = value;
        }
    }
    
    return serialized;
}

function serializeCredentialRequestOptions(options: PublicKeyCredentialRequestOptions): SerializedPublicKeyCredentialRequestOptions {
    const publicKey = options;
    const serializedPublicKey: SerializedPublicKeyCredentialRequestOptions = {
        challenge: bufferToBase64Url(publicKey.challenge as ArrayBuffer)
    };

    // Add optional properties if they exist
    if (publicKey.allowCredentials) {
        serializedPublicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
            id: bufferToBase64Url(cred.id as ArrayBuffer),
            type: cred.type,
            transports: cred.transports
        }));
    }

    if (publicKey.extensions) {
        serializedPublicKey.extensions = publicKey.extensions;
    }

    if (publicKey.rpId) {
        serializedPublicKey.rpId = publicKey.rpId;
    }

    if (publicKey.timeout !== undefined) {
        serializedPublicKey.timeout = publicKey.timeout;
    }

    if (publicKey.userVerification) {
        serializedPublicKey.userVerification = publicKey.userVerification;
    }

    return serializedPublicKey;
}

// Parse function
function parseWebAuthnCredentialGet(credentialJson: any): PublicKeyCredential {

    const rawId = base64UrlToBuffer(credentialJson.rawId);
    const type = credentialJson.type;
    const id = credentialJson.id;
    const clientData = base64UrlToBuffer(credentialJson.response.clientDataJSON);
    const authenticatorData = base64UrlToBuffer(credentialJson.response.authenticatorData);
    const signature = base64UrlToBuffer(credentialJson.response.signature);
    const userHandle = credentialJson.response.userHandle ? base64UrlToBuffer(credentialJson.response.userHandle) : null;

    const authResponse: AuthenticatorAssertionResponse = {
        authenticatorData, signature, userHandle,
        clientDataJSON: clientData
    };

    return {
        authenticatorAttachment: credentialJson.authenticatorAttachment,
        rawId: rawId,
        response: authResponse,
        getClientExtensionResults: function (): AuthenticationExtensionsClientOutputs {
            return {}
        },
        toJSON: function () {
            return credentialJson
        },
        id,
        type
    }

}

function parseWebAuthnCredentialCreate(credentialJson: any): PublicKeyCredential {

    const rawId = base64UrlToBuffer(credentialJson.rawId);
    const type = credentialJson.type;
    const id = credentialJson.id;
    const clientData = base64UrlToBuffer(credentialJson.response.clientDataJSON);
    const attestationObject = base64UrlToBuffer(credentialJson.response.attestationObject);
    const authenticatorData = base64UrlToBuffer(credentialJson.response.authenticatorData);
    const publicKey = base64UrlToBuffer(credentialJson.response.publicKey);
    const publicKeyAlgorithm = credentialJson.response.publicKeyAlgorithm;
    const transports: string[] = credentialJson.response.transports;

    const authResponse: AuthenticatorAttestationResponse = {
        attestationObject: attestationObject, clientDataJSON: clientData,
        getAuthenticatorData(): ArrayBuffer {
            return authenticatorData;
        },
        getPublicKey(): ArrayBuffer | null {
            return publicKey;
        },
        getPublicKeyAlgorithm() {
            return publicKeyAlgorithm;
        },
        getTransports(): string[] {
            return transports;
        }
    };

    return {
        authenticatorAttachment: credentialJson.authenticatorAttachment,
        rawId: rawId,
        response: authResponse,
        getClientExtensionResults: function (): AuthenticationExtensionsClientOutputs {
            return {}
        },
        toJSON(): PublicKeyCredentialJSON {
            return credentialJson
        },
        id,
        type
    }

}

// Helper functions
function base64UrlToBuffer(base64Url: string): ArrayBuffer {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function createCredential(cred: PublicKeyCredentialCreationOptions) {

    const webSafeRequest = serializeWebAuthnCredential(cred);

    return await invoke<{ pubKeyJson?: string }>("plugin:p256-signer|create_credential", {
        payload: {
            creationParams: JSON.stringify(webSafeRequest)
        }
    }).then(({pubKeyJson}) => {
        return parseWebAuthnCredentialCreate(JSON.parse(pubKeyJson!))
    });
}

export async function getCredential(getParams: CredentialRequestOptions): Promise<PublicKeyCredential> {
    const serializedParams = serializeCredentialRequestOptions(getParams.publicKey!);

    return await invoke<{ pubKeyJson?: string }>("plugin:p256-signer|get_credential", {
        payload: {
            getParams: JSON.stringify(serializedParams)
        }
    }).then(({pubKeyJson}) => {
        const pubKey = parseWebAuthnCredentialGet(JSON.parse(pubKeyJson!));
        const cred: any = {
            ...pubKey,
            response: {
                ...pubKey.response,
            },
            getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
                return {};
            }
        }
        return cred;
    });
}