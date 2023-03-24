//
//  File 2.swift
//  
//
//  Created by Hayrettin İletmiş on 24.03.2023.
//

import Foundation

extension Array where Element == UInt8 {

    static func secureRandom(count: Int) -> [UInt8]? {
        var array = [UInt8](repeating: 0, count: count)

        let fd = open("/dev/urandom", O_RDONLY)
        guard fd != -1 else {
            return nil
        }
        defer {
            close(fd)
        }

        let ret = read(fd, &array, MemoryLayout<UInt8>.size * array.count)
        guard ret > 0 else {
            return nil
        }

        return array
    }
}


// MARK: - Errors

public enum KeyError: Error {

    case internalError
    case keyMalformed
    case pubKeyGenerationFailed
}
