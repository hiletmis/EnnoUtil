
import Foundation 
import B58
import Curve25519
import Ed25519
import Web3Util

public typealias Base58 = String
public typealias Base64 = String
public typealias Bytes = [UInt8]
public typealias PublicKey = String
public typealias PrivateKey = String
public typealias Seed = String
public typealias Address = String

public typealias Web3AddressHex = String
public typealias Web3PrivateKeyHex = String
public typealias Web3PublicKeyHex = String
public typealias Web3ExtPrivateKeyHex = String
public typealias Web3ExtPublicKeyHex = String
public typealias Web3Account = Account

public typealias AvalancheNativeAddress = String

public struct KeyPair {
    public let publicKey: PublicKey
    public let privateKey: PrivateKey
}

public struct Account {
    public let address: Web3AddressHex
    public let publicKey: Web3PublicKeyHex
    public let privateKey: Web3PrivateKeyHex
}

public enum Entropy: Int {
    case e32 = 3
    case e64 = 6
    case e96 = 9
    case e128 = 12
    case e160 = 15
    case e192 = 18
    case e224 = 21
    case e256 = 24
}

public enum ChainId {
    public static let ethereum: Int = 60
    public static let avalanche: Int = 43114
    public static let avalancheC: Int = 9005
    public static let avalancheX: Int = 9000
    public static let solana: Int = 501
    public static let binance: Int = 56
    public static let polygon: Int = 137
    public static let bitcoin: Int = 0
}

public enum CryptoConstants {
    public static let publicKeyLength: Int = 32
    public static let privateKeyLength: Int = 32
    public static let signatureLength: Int = 64
    
    internal static let keyLength: Int = 32
    internal static let addressVersion: UInt8 = 1
    internal static let checksumLength: Int = 4
    internal static let hashLength: Int = 20
    internal static let addressLength: Int = 1 + 1 + hashLength + checksumLength
}

public enum VersionBytes: String {
    public typealias RawValue = String
        
    case mainnetPublic = "0488b21e"
    case mainnetPrivate = "0488ade4"
    case testnetPublic = "043587cf"
    case testnetPrivate = "04358394"
}

public class CryptoUtil: CryptoUtilProtocol {
    
    public init() {}
    
    public static let shared: CryptoUtil = CryptoUtil()

    public func address(publicKey: PublicKey, chainId: UInt8?) -> Address? {
        
        guard let publicKeyDecode = base58decode(input: publicKey) else { return nil }
        
        let bytes = secureHash(publicKeyDecode)
        let publicKeyHash = Array(bytes[0..<CryptoConstants.hashLength])
        
        let withoutChecksum: Bytes = [CryptoConstants.addressVersion, UInt8(chainId ?? 0)] + publicKeyHash
        let checksum = calcCheckSum(withoutChecksum)
        
        return base58encode(input: withoutChecksum + checksum)
    }
    
    public func address(seed: Seed, chainId: UInt8?) -> Address? {
        
        guard let key = publicKey(seed: seed) else { return nil }
        
        return address(publicKey: key, chainId: chainId)
    }
    
    public func web3address(seed: Seed, path: String) -> Web3AddressHex? {
        let keypair = Web3Crypto.shared.getBip32Key(seed: seed)
        guard let address = Web3Crypto.shared.deriveAddress(path: path, key: keypair) else { return nil }
        return "0x" + address.toHexString()
    }
    
    public func web3address(xPriv: Web3ExtPrivateKeyHex, depth: Int, index: Int) -> Web3AddressHex? {
        guard let address = Web3Crypto.shared.deriveAddress(xPriv: xPriv, index: index) else { return nil }
        return "0x" + address.toHexString()
    }
    
    public func web3Account(seed: Seed, path: String) -> Web3Account? {
        if Web3Crypto.shared.validateMnemonic(seed: seed) {
            let keypair = Web3Crypto.shared.getBip32Key(seed: seed)
            return Web3Crypto.shared.Account(path: path, key: keypair)
        } else {
            return nil
        }
    }
    
    public func web3xPrv(seed: Seed, path: String) -> Web3ExtPrivateKeyHex? {
        let keypair = Web3Crypto.shared.getBip32Key(seed: seed)
        if let key = Web3Crypto.shared.deriveExtKey(path: path, key: keypair) {
            return Base58Encoder.encode(key)
        }
        return nil
    }
    
    public func web3xPub(seed: Seed, path: String) -> Web3ExtPrivateKeyHex? {
        let keypair = Web3Crypto.shared.getBip32Key(seed: seed)
        if let key = Web3Crypto.shared.deriveExtKey(path: path, key: keypair, xPub: true) {
            return Base58Encoder.encode(key)
        }
        return nil
    }
    
    public func avaxNativeAddress(xPriv: [UInt8], hrp: String) -> AvalancheNativeAddress? {
        return Web3Crypto.shared.bech32Address(privKey: xPriv, hrp: hrp)
    }
    
    public func avaxNativeAddress(ripesha: [UInt8], hrp: String) -> AvalancheNativeAddress? {
        return Web3Crypto.shared.bech32Address(ripesha: ripesha, hrp: hrp)
    }
    
    public func signBytes(bytes: Bytes, privateKey: PrivateKey) -> Bytes? {
        
        guard let privateKeyDecode = base58decode(input: privateKey) else { return nil }
        
        return Array(Curve25519.sign(Data(bytes), withPrivateKey: Data(privateKeyDecode)))
    }

    public func signBytes(bytes: Bytes, seed: Seed) -> Bytes? {
        
        guard let pair = keyPair(seed: seed) else { return nil }
        
        return signBytes(bytes: bytes, privateKey: pair.privateKey)
    }
    
    public func verifySignature(publicKey: PublicKey, bytes: Bytes, signature: Bytes) -> Bool {
        
        guard let publicKeyDecode = base58decode(input: publicKey) else { return false }
        
        return Ed25519.verifySignature(Data(signature), publicKey: Data(publicKeyDecode), data: Data(bytes))
    }

    public func verifyPublicKey(publicKey: PublicKey) -> Bool {
        
        guard let publicKeyDecode = base58decode(input: publicKey) else { return false }
        
        return publicKeyDecode.count == CryptoConstants.keyLength
    }

    public func verifyAddress(address: Address, chainId: UInt8?, publicKey: PublicKey?) -> Bool {
        
        if let publicKey = publicKey {
            return self.verifyPublicKey(publicKey: publicKey)
        }
        
        guard let bytes = base58decode(input: address) else { return false }
        
        if bytes.count == CryptoConstants.addressLength
            && bytes[0] == CryptoConstants.addressVersion
            && bytes[1] == UInt8(chainId ?? 0) {
            let checkSum = Array(bytes[bytes.count - CryptoConstants.checksumLength..<bytes.count])
            let checkSumGenerated = calcCheckSum(Array(bytes[0..<bytes.count - CryptoConstants.checksumLength]))
            
            return checkSum == checkSumGenerated
        }
        
        return false
    }
}

// MARK: - Methods are creating keys

extension CryptoUtil {
    
    public func keyPair(seed: Seed) -> KeyPair? {
        
        let seedData = Data(seedHash(Array(seed.utf8)))
        
        guard let pair = Curve25519.generateKeyPair(seedData) else { return nil }
        
        guard let privateKeyData = pair.privateKey() else { return nil }
        let privateKeyBytes = privateKeyData.withUnsafeBytes {
            [UInt8]($0)
        }
        
        guard let publicKeyData = pair.publicKey() else { return nil }
        let publicKeyBytes = publicKeyData.withUnsafeBytes {
            [UInt8]($0)
        }
        
        guard let privateKey = base58encode(input: privateKeyBytes) else { return nil }
        guard let publicKey = base58encode(input: publicKeyBytes) else { return nil }
        
        return KeyPair(publicKey: publicKey,
                       privateKey: privateKey)
        
    }
    
    public func publicKey(seed: Seed) -> PublicKey? {
        return keyPair(seed: seed)?.publicKey
    }
    
    public func privateKey(seed: Seed) -> PrivateKey? {
        return keyPair(seed: seed)?.privateKey
    }
    
    public func randomSeed(entropy: Entropy = .e256) -> Seed {
        return generatePhrase(entropy: entropy)
    }
    
}

// MARK: - Methods Hash

extension CryptoUtil {
    
    public func blake2b256(input: Bytes) -> Bytes {
        CryptoFx.blake2b256(input: input)
    }
    
    public func keccak256(input: Bytes) -> Bytes {
        CryptoFx.keccak256(input: input)
    }
    
    public func sha256(input: Bytes) -> Bytes {
        CryptoFx.sha256(input: input)
    }
}

// MARK: - Method for encode/decode base58/64

extension CryptoUtil {
    
    public func base58encode(input: Bytes) -> String? {
        
        let result = Base58Encoder.encode(input)
        
        if result.count == 0 {
            return nil
        }
        
        return result
    }
    
    public func base58decode(input: String) -> Bytes? {
        
        let result = Base58Encoder.decode(input)
        
        if result.count == 0 {
            return nil
        }
        
        return result
    }
    
    public func base64encode(input: Bytes) -> String {
        return Data(input).base64EncodedString()
    }
    
    public func base64decode(input: String) -> Bytes? {
        
        var clearInput = input
        
        if let range = input.range(of: "base64:") {
            clearInput.removeSubrange(range)
        }
        
        guard let data = Data(base64Encoded: clearInput) else { return nil }
        
        return Array(data)
    }
}

// MARK: - Hash for seed

private extension CryptoUtil {
    
    
    func secureHash(_ input: Bytes) -> Bytes {
        return keccak256(input: blake2b256(input: input))
    }
    
    func seedHash(_ seed: Bytes) -> Bytes {
        
        let nonce: [UInt8] = [0, 0, 0, 0]
        let input = nonce + seed

        return sha256(input: secureHash(input))
    }
    
    func calcCheckSum(_ withoutChecksum: Bytes) -> Bytes {
        return Array(secureHash(withoutChecksum)[0..<CryptoConstants.checksumLength])
    }

}

// MARK: - Generate Phrase

private extension CryptoUtil {
    
    private func randomBytes(_ length: Int) -> Bytes {
        
        var data = Data(count: length)
        
        data.withUnsafeMutableBytes { (rawPointer) -> Void in
            guard let bytes = rawPointer.bindMemory(to: UInt8.self).baseAddress else { return }
            let _ = SecRandomCopyBytes(kSecRandomDefault, length, bytes)
        }
        
        return Array(data)
    }
    
    private func bytesToBits(_ data: Bytes) -> [Bool] {
        
        var bits: [Bool] = []
        for i in 0..<data.count {
            for j in 0..<8 {
                bits.append((data[i] & UInt8(1 << (7 - j))) != 0)
            }
        }
        return bits
    }
    
    private func generatePhrase(entropy: Entropy) -> String {
        let nbWords = entropy.rawValue;
        let len = nbWords / 3 * 4;
        let entropy = randomBytes(len)
        
        let hash = sha256(input: entropy)
        let hashBits = bytesToBits(hash)
        
        let entropyBits = bytesToBits(entropy)
        let checksumLengthBits = entropyBits.count / 32
        
        let concatBits = entropyBits + hashBits[0..<checksumLengthBits]
        
        var words: [String] = []
        let nwords = concatBits.count / 11
        for i in 0..<nwords {
            var index = 0
            for j in 0..<11 {
                index <<= 1
                if concatBits[(i * 11) + j] { index |= 0x1 }
            }
            words += [Words.list[index]]
        }
        
        return words.joined(separator: " ")
    }
}


