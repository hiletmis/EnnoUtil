//
//  Web3PrivateKey.swift
//  Web3
//
//  Created by Koray Koska on 06.02.18.
//  Copyright © 2018 Boilertalk. All rights reserved.
//

import Foundation
import secp256k1
import Crypto

public struct Web3PrivateKey {

    // MARK: - Properties

    /// The raw private key bytes
    public let rawPrivateKey: [UInt8]

    /// True iff ctx should not be freed on deinit
    private let ctxSelfManaged: Bool

    /// Internal context for secp256k1 library calls
    private let ctx: OpaquePointer

    // MARK: - Initialization

    /**
     * Initializes a new cryptographically secure `Web3PrivateKey` from random noise.
     *
     * The process of generating the new private key is as follows:
     *
     * - Generate a secure random number between 55 and 65.590. Call it `rand`.
     * - Read `rand` bytes from `/dev/urandom` and call it `bytes`.
     * - Create the keccak256 hash of `bytes` and initialize this private key with the generated hash.
     */

    /**
     * Initializes a new instance of `EthereumPrivateKey` with the given `privateKey` Bytes.
     *
     * `privateKey` must be exactly a big endian 32 Byte array representing the private key.
     *
     * The number must be in the secp256k1 range as described in: https://en.bitcoin.it/wiki/Private_key
     *
     * So any number between
     *
     * 0x0000000000000000000000000000000000000000000000000000000000000001
     *
     * and
     *
     * 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
     *
     * is considered to be a valid secp256k1 private key.
     *
     * - parameter privateKey: The private key bytes.
     *
     * - parameter ctx: An optional self managed context. If you have specific requirements and
     *                  your app performs not as fast as you want it to, you can manage the
     *                  `secp256k1_context` yourself with the public methods
     *                  `secp256k1_default_ctx_create` and `secp256k1_default_ctx_destroy`.
     *                  If you do this, we will not be able to free memory automatically and you
     *                  __have__ to destroy the context yourself once your app is closed or
     *                  you are sure it will not be used any longer. Only use this optional
     *                  context management if you know exactly what you are doing and you really
     *                  need it.
     *
     * - throws: EthereumPrivateKey.Error.keyMalformed if the restrictions described above are not met.
     *           EthereumPrivateKey.Error.internalError if a secp256k1 library call or another internal call fails.
     *           EthereumPrivateKey.Error.pubKeyGenerationFailed if the public key extraction from the private key fails.
     */
    public init(privateKey: [UInt8], ctx: OpaquePointer? = nil) throws {
        guard privateKey.count == 32 else {
            throw KeyError.keyMalformed
        }
        self.rawPrivateKey = privateKey

        let finalCtx: OpaquePointer
        if let ctx = ctx {
            finalCtx = ctx
            self.ctxSelfManaged = true
        } else {
            let ctx = Crypto.shared.secp256k1Ctx
            finalCtx = ctx
            self.ctxSelfManaged = false
        }
        self.ctx = finalCtx

        // *** Generate public key ***
        guard let pubKey = malloc(MemoryLayout<secp256k1_pubkey>.size)?.assumingMemoryBound(to: secp256k1_pubkey.self) else {
            throw KeyError.internalError
        }
        // Cleanup
        defer {
            free(pubKey)
        }
        var secret = privateKey
        if secp256k1_ec_pubkey_create(finalCtx, pubKey, &secret) != 1 {
            throw KeyError.pubKeyGenerationFailed
        }

        // Verify private key
        try verifyPrivateKey()
    }

    // MARK: - Convenient functions

    public func sign(message: [UInt8], hashSHA3: Bool = true) throws -> (v: UInt, r: [UInt8], s: [UInt8]) {
        var hash = hashSHA3 ? SHA3(variant: .keccak256).calculate(for: message) : message
        
        guard hash.count == 32 else {
            throw KeyError.internalError
        }
        guard let sig = malloc(MemoryLayout<secp256k1_ecdsa_recoverable_signature>.size)?.assumingMemoryBound(to: secp256k1_ecdsa_recoverable_signature.self) else {
            throw KeyError.internalError
        }
        defer {
            free(sig)
        }

        var seckey = rawPrivateKey

        guard secp256k1_ecdsa_sign_recoverable(ctx, sig, &hash, &seckey, nil, nil) == 1 else {
            throw KeyError.internalError
        }

        var output64 = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &output64, &recid, sig)

        guard recid == 0 || recid == 1 else {
            // Well I guess this one should never happen but to avoid bigger problems...
            throw KeyError.internalError
        }

        return (v: UInt(recid), r: Array(output64[0..<32]), s: Array(output64[32..<64]))
    }

    /**
     * Returns this private key serialized as a hex string.
     */
    public func hex() -> String {
        var h = "0x"
        for b in rawPrivateKey {
            h += String(format: "%02x", b)
        }

        return h
    }

    // MARK: - Helper functions

    private func verifyPrivateKey() throws {
        var secret = rawPrivateKey
        guard secp256k1_ec_seckey_verify(ctx, &secret) == 1 else {
            throw KeyError.keyMalformed
        }
    }

    // MARK: - Errors

    public enum KeyError: Error {

        case internalError
        case keyMalformed
        case pubKeyGenerationFailed
    }
    
}

// MARK: - Equatable

extension Web3PrivateKey: Equatable {

    public static func ==(_ lhs: Web3PrivateKey, _ rhs: Web3PrivateKey) -> Bool {
        return lhs.rawPrivateKey == rhs.rawPrivateKey
    }
}

// MARK: - Hashable

extension Web3PrivateKey: Hashable {

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawPrivateKey)
    }
}

