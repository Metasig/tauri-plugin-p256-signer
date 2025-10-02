
import Foundation

enum Base64URLError: Error {
    case invalid
}

public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        let s = data.base64EncodedString()
        return s
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ s: String) throws -> Data {
        var str = s.replacingOccurrences(of: "-", with: "+")
                   .replacingOccurrences(of: "_", with: "/")
        let padLen = (4 - (str.count % 4)) % 4
        if padLen > 0 {
            str += String(repeating: "=", count: padLen)
        }
        guard let data = Data(base64Encoded: str) else { throw Base64URLError.invalid }
        return data
    }
}
