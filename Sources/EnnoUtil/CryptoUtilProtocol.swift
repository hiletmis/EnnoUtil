//
//  File.swift
//  
//
//  Created by Hayrettin İletmiş on 30.03.2023.
//

import Foundation

public protocol CryptoUtilProtocol {

    /**
     BLAKE2 are cryptographic hash function

     - Parameter: input byte array of input data
     - Returns: byte array of hash values
     */
    func blake2b256(input: Bytes) -> Bytes

    /**
     Keccak are secure hash algorithm

     - Parameter: input byte array of input data
     - Returns: byte array of hash values
     */
    func keccak256(input: Bytes) -> Bytes

    /**
     SHA-256 are cryptographic hash function

     - Parameter: input byte array of input data
     - Returns: byte array of hash values
     */
    func sha256(input: Bytes) -> Bytes

    /**
     Base58 binary-to-text encoding function used to represent large integers as alphanumeric text.
     Compared to Base64 like in base64encode(), the following similar-looking letters are omitted:
     0 (zero), O (capital o), I (capital i) and l (lower case L) as well
     as the non-alphanumeric characters + (plus) and / (slash)

     - Parameter: input byte array containing binary data to encode
     - Returns: encoded string containing Base58 characters
     */
    func base58encode(input: Bytes) -> String?

    /**
     Base58 text-to-binary function used to restore data encoded by Base58,
     reverse of base58encode()

     - Parameter: input encoded Base58 string
     - Returns: decoded byte array
     */
    func base58decode(input: String) -> Bytes?

    /**
      Base64 binary-to-text encoding function used to represent binary data in an ASCII
      string format by translating it into a radix-64 representation.
      The implementation uses A–Z, a–z, and 0–9 for the first 62 values and '+', '/'

      - Parameter: input byte array containing binary data to encode.
      - Returns: String containing Base64 characters
     */
    func base64encode(input: Bytes) -> String

    /**
     Base64 text-to-binary function used to restore data encoded by Base64,
     reverse of base64encode()

     - Parameter: input encoded Base64 string
     - Returns: decoded byte array
     */
    func base64decode(input: String) -> Bytes?

    /**
     Random Seed-phrase generator from 2048 prepared words.
     It is a list of words which store all the information needed to recover a private key
     - Returns: a new randomly generated BIP39 seed-phrase
     */
    func randomSeed(entropy: Entropy) -> Seed

    /**
     - Returns: a public and private key-pair by seed-phrase
     */
    func keyPair(seed: Seed) -> KeyPair?

    /**
     - Returns: a public key as String by seed-phrase
     */
    func publicKey(seed: Seed) -> PublicKey?

    /**
     - Returns: a private key as String by seed-phrase
     */
    func privateKey(seed: Seed) -> PrivateKey?

    /**
     - Returns: a new generated Waves address as String from the publicKey and chainId
     */
    func address(publicKey: PublicKey, chainId: UInt8?) -> Address?

    /**
     - Returns: a new generated Waves address as String from the seed-phrase
     */
    func address(seed: Seed, chainId: UInt8?) -> Address?
    /**
     - Returns: a new generated Web3 address as String from the seed-phrase
     */
    func web3address(seed: Seed, path: String) -> Web3AddressHex?
    /**
    - Returns: a new generated Web3 address as String from the extended private key.
    */
   func web3address(xPriv: Web3ExtPrivateKeyHex, depth: Int, index: Int) -> Web3AddressHex?
    /**
    - Returns: a new generated Avalanche Native address as String from the extended private key.
    */
    func avaxNativeAddress(xPriv: [UInt8], hrp: String) -> AvalancheNativeAddress?
    /**
    - Returns: a new generated Avalanche Native address as String from the hash160(privKey).
    */
    func avaxNativeAddress(ripesha: [UInt8], hrp: String) -> AvalancheNativeAddress?
   
    /**
     - Returns: a new generated Web3 account as object from the seed-phrase
     */
    func web3Account(seed: Seed, path: String) -> Web3Account?
    
    /**
     - Returns: a new generated account's external private key from the seed-phrase
     */
    func web3xPrv(seed: Seed, path: String) -> Web3ExtPrivateKeyHex?
    
    /**
     - Returns: a new generated account's external public key from the seed-phrase
     */
    func web3xPub(seed: Seed, path: String) -> Web3ExtPublicKeyHex?

    /**
     - Parameter: privateKey is a key to an address that gives access
     to the management of the tokens on that address as String.
     It is string encoded by Base58 from byte array.
     - Returns: signature for the bytes by privateKey as byte array
     */
    func signBytes(bytes: Bytes, privateKey: PrivateKey) -> Bytes?

    /**
     - Returns: signature for the bytes by seed-phrase as byte array
     */
    func signBytes(bytes: Bytes, seed: Seed) -> Bytes?

    /**
     - Returns: true if signature is a valid signature of bytes by publicKey
     */
    func verifySignature(publicKey: PublicKey, bytes: Bytes, signature: Bytes) -> Bool

    /**
     - Returns: true if publicKey is a valid public key
     */
    func verifyPublicKey(publicKey: PublicKey) -> Bool

    /**
     Checks address for a valid by optional chainId and publicKey params
     If params non null it iss will be checked.
     - Parameter: address a unique identifier of an account on the Waves blockchain
     - Parameter: chainId it is id of blockchain network 'W' for production and 'T' for test net
     - Parameter: publicKey
     - Returns: true if address is a valid Waves address for optional chainId and publicKey
     */
    func verifyAddress(address: Address, chainId: UInt8?, publicKey: PublicKey?) -> Bool
}
 
