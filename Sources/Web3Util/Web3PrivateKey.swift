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

