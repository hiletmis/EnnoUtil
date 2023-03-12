//
//  UInt8+Byte.swift
//  WavesWallet-iOS
//
//  Created by mefilt on 23.07.2018.
//  Copyright © 2018 Waves Platform. All rights reserved.
//

import Foundation

public func toByteArray<T>(_ value: T) -> [UInt8] {
    var value = value
    return (withUnsafeBytes(of: &value) { Array($0) }).reversed()
}

public extension NumberFormatter {

    static func sharedFormatter(key: String) -> NumberFormatter {
        return Thread
            .threadSharedObject(key: key,
                                create: { return NumberFormatter() })
    }
}

public extension RIPEMD160 {

    static func hash(message: Data) -> Data {
        var md = RIPEMD160()
        md.update(data: message)
        return md.finalize()
    }

    static func hash(message: String) -> Data {
        return RIPEMD160.hash(message: message.data(using: .utf8)!)
    }
}
