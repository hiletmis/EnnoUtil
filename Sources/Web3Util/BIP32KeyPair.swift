public enum BIP32KeyTag: UInt8 {
    case template = 0xA1
    case pubKey = 0x80
    case privKey = 0x81
    case chainCode = 0x82
}

public struct BIP32KeyPair {
    public let privateKey: [UInt8]?
    public let chainCode: [UInt8]?
    public let publicKey: [UInt8]
    
    public var isPublicOnly: Bool { get { privateKey == nil } }
    public var isExtended: Bool { get { chainCode != nil } }
    
    public init(privateKey: [UInt8]?, chainCode: [UInt8]?, publicKey: [UInt8]?) {
        precondition(privateKey != nil || (chainCode == nil && publicKey != nil))
        
        if (privateKey != nil) {
            self.privateKey = Util.shared.dropZeroPrefix(uint8: privateKey!)
        } else {
            self.privateKey = privateKey
        }
        
        self.chainCode = chainCode
        
        if let pubKey = publicKey {
            self.publicKey = pubKey
        } else {
            self.publicKey = Crypto.shared.secp256k1PublicFromPrivate(privateKey!)
        }
    }
    
    public init(fromSeed binarySeed: [UInt8]) {
        let mac = Crypto.shared.hmacSHA512(data: binarySeed, key: Array("Bitcoin seed".utf8))
        self.init(privateKey: Array(mac[0..<32]), chainCode: Array(mac[32...]), publicKey: nil)
    }
    
    public func toEthereumAddress() -> [UInt8] {
        Crypto.shared.secp256k1PublicToEthereumAddress(self.publicKey)
    }
    
}

public class Key {
    public class func getPublicFromPrivateKey(privKey: [UInt8], compressed: Bool = false) -> String {
        Crypto.shared.secp256k1PublicFromPrivate(privKey, compressed).toHexString()
    }
    
    public class func getAddressFromPublicKey(publicKey: [UInt8]) -> String {
        Crypto.shared.secp256k1PublicToEthereumAddress(publicKey).toHexString()
    }
    
    public class func getAddressFromPrivateKey(privKey: [UInt8]) -> String {
        let publicKey = Crypto.shared.secp256k1PublicFromPrivate(privKey)
        return Crypto.shared.secp256k1PublicToEthereumAddress(publicKey).toHexString()
    }
}

public class HashMAC {
    public class func getHMAC512(data: [UInt8], key: [UInt8]) -> [UInt8]? {
        return Crypto.shared.hmacSHA512(data: data, key: key)
    }
    
}

