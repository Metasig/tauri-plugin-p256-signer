import Foundation

enum CBORDecodeError: Error {
    case invalidData
    case unsupportedType
    case unexpectedEndOfData
    case invalidFormat
}

class SimpleCBORDecoder {
    static func decode(_ data: Data) throws -> Any {
        var iterator = data.makeIterator()
        return try decodeItem(from: &iterator)
    }
    
    static func decode(_ bytes: [UInt8]) throws -> Any {
        var iterator = bytes.makeIterator()
        return try decodeItem(from: &iterator)
    }
    
    private static func decodeItem<T: IteratorProtocol>(from iterator: inout T) throws -> Any
    where T.Element == UInt8 {
        guard let firstByte = iterator.next() else {
            throw CBORDecodeError.unexpectedEndOfData
        }
        
        let majorType = firstByte >> 5
        let minorBits = firstByte & 0x1F
        
        switch majorType {
        case 0:  // Unsigned integer
            return try decodeUnsignedInteger(minorBits, from: &iterator)
        case 1:  // Negative integer
            let value = try decodeUnsignedInteger(minorBits, from: &iterator)
            return -1 - Int(value)
        case 2:  // Byte string
            let length = try decodeUnsignedInteger(minorBits, from: &iterator)
            return try decodeByteString(length: Int(length), from: &iterator)
        case 3:  // Text string
            let length = try decodeUnsignedInteger(minorBits, from: &iterator)
            return try decodeTextString(length: Int(length), from: &iterator)
        case 4:  // Array
            let count = try decodeUnsignedInteger(minorBits, from: &iterator)
            return try decodeArray(count: Int(count), from: &iterator)
        case 5:  // Map
            let count = try decodeUnsignedInteger(minorBits, from: &iterator)
            return try decodeMap(count: Int(count), from: &iterator)
        case 6:  // Tagged data
            _ = try decodeUnsignedInteger(minorBits, from: &iterator)
            return try decodeItem(from: &iterator)
        case 7:  // Simple/Float
            if minorBits == 20 { return false }
            if minorBits == 21 { return true }
            if minorBits == 22 { return NSNull() }
            if minorBits == 23 { return NSNull() }
            
            if minorBits == 24 {
                guard let simpleValue = iterator.next() else {
                    throw CBORDecodeError.unexpectedEndOfData
                }
                return Int(simpleValue)
            }
            
            if minorBits == 25 { // Half-precision float (16 bits)
                guard let byte1 = iterator.next(), let byte2 = iterator.next() else {
                    throw CBORDecodeError.unexpectedEndOfData
                }
                // Proper half-precision float decoding is complex, simplified here
                return Double(UInt16(byte1) << 8 | UInt16(byte2)) / 100.0
            }
            
            if minorBits == 26 { // Single-precision float (32 bits)
                guard let byte1 = iterator.next(), let byte2 = iterator.next(),
                      let byte3 = iterator.next(), let byte4 = iterator.next() else {
                    throw CBORDecodeError.unexpectedEndOfData
                }
                
                let bits = UInt32(byte1) << 24 | UInt32(byte2) << 16 | UInt32(byte3) << 8 | UInt32(byte4)
                return Float(bitPattern: bits)
            }
            
            if minorBits == 27 { // Double-precision float (64 bits)
                guard let byte1 = iterator.next(), let byte2 = iterator.next(),
                      let byte3 = iterator.next(), let byte4 = iterator.next(),
                      let byte5 = iterator.next(), let byte6 = iterator.next(),
                      let byte7 = iterator.next(), let byte8 = iterator.next() else {
                    throw CBORDecodeError.unexpectedEndOfData
                }
                
                let bits = UInt64(byte1) << 56 | UInt64(byte2) << 48 | UInt64(byte3) << 40 | UInt64(byte4) << 32 |
                UInt64(byte5) << 24 | UInt64(byte6) << 16 | UInt64(byte7) << 8 | UInt64(byte8)
                return Double(bitPattern: bits)
            }
            
            throw CBORDecodeError.unsupportedType
        default:
            throw CBORDecodeError.unsupportedType
        }
    }
    
    private static func decodeUnsignedInteger<T: IteratorProtocol>(
        _ additionalInfo: UInt8, from iterator: inout T
    ) throws -> UInt64 where T.Element == UInt8 {
        switch additionalInfo {
        case 0...23:
            return UInt64(additionalInfo)
        case 24:
            guard let byte = iterator.next() else { throw CBORDecodeError.unexpectedEndOfData }
            return UInt64(byte)
        case 25:
            guard let byte1 = iterator.next(), let byte2 = iterator.next() else {
                throw CBORDecodeError.unexpectedEndOfData
            }
            return UInt64(byte1) << 8 | UInt64(byte2)
        case 26:
            guard let byte1 = iterator.next(), let byte2 = iterator.next(),
                  let byte3 = iterator.next(), let byte4 = iterator.next()
            else { throw CBORDecodeError.unexpectedEndOfData }
            return UInt64(byte1) << 24 | UInt64(byte2) << 16 | UInt64(byte3) << 8 | UInt64(byte4)
        case 27:
            guard let byte1 = iterator.next(), let byte2 = iterator.next(),
                  let byte3 = iterator.next(), let byte4 = iterator.next(),
                  let byte5 = iterator.next(), let byte6 = iterator.next(),
                  let byte7 = iterator.next(), let byte8 = iterator.next()
            else { throw CBORDecodeError.unexpectedEndOfData }
            return UInt64(byte1) << 56 | UInt64(byte2) << 48 | UInt64(byte3) << 40 | UInt64(byte4)
            << 32 | UInt64(byte5) << 24 | UInt64(byte6) << 16 | UInt64(byte7) << 8
            | UInt64(byte8)
        default:
            throw CBORDecodeError.unsupportedType
        }
    }
    
    private static func decodeByteString<T: IteratorProtocol>(length: Int, from iterator: inout T)
    throws -> Data where T.Element == UInt8
    {
        var bytes = [UInt8]()
        for _ in 0..<length {
            guard let byte = iterator.next() else { throw CBORDecodeError.unexpectedEndOfData }
            bytes.append(byte)
        }
        return Data(bytes)
    }
    
    private static func decodeTextString<T: IteratorProtocol>(length: Int, from iterator: inout T)
    throws -> String where T.Element == UInt8
    {
        let data = try decodeByteString(length: length, from: &iterator)
        guard let string = String(data: data, encoding: .utf8) else {
            throw CBORDecodeError.invalidData
        }
        return string
    }
    
    private static func decodeArray<T: IteratorProtocol>(count: Int, from iterator: inout T) throws
    -> [Any] where T.Element == UInt8
    {
        var array = [Any]()
        for _ in 0..<count {
            let item = try decodeItem(from: &iterator)
            array.append(item)
        }
        return array
    }
    
    private static func decodeMap<T: IteratorProtocol>(
        count: Int, from iterator: inout T
    ) throws -> [AnyHashable: Any] where T.Element == UInt8 {
        var map = [AnyHashable: Any]()
        for _ in 0..<count {
            let key = try decodeItem(from: &iterator)
            let value = try decodeItem(from: &iterator)
            if let hashableKey = makeHashable(key) {
                map[hashableKey] = value
            } else {
                throw CBORDecodeError.invalidData
            }
        }
        return map
    }
    
    private static func makeHashable(_ item: Any) -> AnyHashable? {
        if let string = item as? String {
            return AnyHashable(string)
        } else if let int = item as? Int {
            return AnyHashable(int)
        } else if let uint = item as? UInt {
            return AnyHashable(uint)
        } else if let int64 = item as? Int64 {
            return AnyHashable(int64)
        } else if let uint64 = item as? UInt64 {
            return AnyHashable(uint64)
        } else if let double = item as? Double {
            return AnyHashable(double)
        } else if let bool = item as? Bool {
            return AnyHashable(bool)
        } else if let data = item as? Data {
            // Create a hashable wrapper for Data
            return AnyHashable(data.description)
        }
        return nil
    }
    
    // Helper method to extract WebAuthn public key from attestation object
    static func extractPublicKey(from attestationObject: Data) -> Data? {
        do {
            guard let cborData = try decode(attestationObject) as? [AnyHashable: Any],
                  let authData = cborData["authData"] as? Data else {
                return nil
            }
            
            // AuthData structure:
            // - rpIdHash (32 bytes)
            // - flags (1 byte)
            // - signCount (4 bytes)
            // - attestedCredentialData (if attested credential data flag is set)
            //   - aaguid (16 bytes)
            //   - credentialIdLength (2 bytes)
            //   - credentialId (credentialIdLength bytes)
            //   - credentialPublicKey (CBOR-encoded)
            
            // Need at least 37 bytes for header
            if authData.count <= 37 {
                return nil
            }
            
            // Check if attested credential data flag is set (bit 6)
            let flags = authData[32]
            let attestedCredentialDataFlag = (flags & 0x40) != 0
            
            if !attestedCredentialDataFlag {
                return nil
            }
            
            let aaguidStart = 37
            let credentialIdLengthStart = aaguidStart + 16
            
            if authData.count <= credentialIdLengthStart + 2 {
                return nil
            }
            
            // Get credential ID length (2 bytes, big-endian)
            let credentialIdLength = UInt16(authData[credentialIdLengthStart]) << 8 |
            UInt16(authData[credentialIdLengthStart + 1])
            
            let credentialIdStart = credentialIdLengthStart + 2
            let credentialPublicKeyStart = credentialIdStart + Int(credentialIdLength)
            
            if authData.count <= credentialPublicKeyStart {
                return nil
            }
            
            // The remaining data is the CBOR-encoded public key
            return authData.subdata(in: credentialPublicKeyStart..<authData.count)
        } catch {
            print("Error extracting public key: \(error)")
            return nil
        }
    }
}
