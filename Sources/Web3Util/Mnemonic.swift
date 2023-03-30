import Foundation

public class Mnemonic {
    static let bip39IterationCount = 2048
    
    public static func toBinarySeed(mnemonicPhrase: String, password: String = "") -> [UInt8] {
        Crypto.shared.pbkdf2(password: mnemonicPhrase,
                             salt: Array(("mnemonic" + password).utf8),
                             iterations: Mnemonic.bip39IterationCount,
                             hmac: PBKDF2HMac.sha512)
    }
}
