//
//  File.swift
//  
//
//  Created by Hayrettin İletmiş on 11.03.2023.
//

import Foundation

class HexUtil {
    
    public class func addHex(a: String, b:String) -> [UInt8] {
        return addHex(a: a.hexToBytes(), b: b.hexToBytes())
    }
    
    public class func addHex(a: [UInt8], b:[UInt8]) -> [UInt8] {

        var result:[UInt8] = []
        
        let size_a = a.count
        let size_b = b.count
        
        if size_a < size_b {
            return addHex(a: b, b: a)
        }
        
        var carry = 0
        for (index, i) in a.reversed().enumerated() {
            let valB = index > b.count - 1 ? 0 : b[(b.count - 1) - index]

            var sum : Int = carry + Int(i) + Int(valB)
            
            if sum > 255 {
                carry = 1
                sum = sum - 255 - 1
            } else {
                carry = 0
            }
            result.append(UInt8(sum))
        }
        
        if carry == 1 {
            result.append(UInt8(1))
        }
        
        return result.reversed()
    }
    
    public class func subtractHex(a: String, b:String) -> [UInt8]? {
        if let result = subtractHex(a: a.hexToBytes(), b: b.hexToBytes()) {
            return result
        }
        return nil
    }
    
    public class func subtractHex(a: [UInt8], b:[UInt8]) -> [UInt8]? {
        var result:[UInt8] = []
        
        let size_a = a.count
        let size_b = b.count
        
        if size_a < size_b {
            return nil
        }
            
        var carry = 0
        
        for (index, i) in a.reversed().enumerated() {
            let valB = index > b.count - 1 ? 0 : b[(b.count - 1) - index]
            var sum : Int = Int(i) - carry - Int(valB)
            
            if sum < 0 {
                carry = 1
                sum = sum + 255 + 1
            } else {
                carry = 0
            }
            result.append(UInt8(sum))
        }
        
        if carry == 1 {
            return nil
        }
        
        result = result.reversed()
        
        for int8 in result {
            if int8 == 0 {
                result.removeFirst()
            } else {
                break
            }
        }
        
        return result
    }
    
    public class func multiplyHex(a: [UInt8], b:[UInt8]) -> [UInt8] {
        var result:[UInt8] = []

        for (index, int8) in b.reversed().enumerated() {
            let times : Int = Int(int8)

            var digit = a

            for _ in 0 ..< (index) {
                digit.append(0)
            }

            for _ in 1...times {
                result = addHex(a: result, b: digit)
            }
        }
        
        return result
    }
    
    public class func modulo(a: [UInt8], b:[UInt8]) -> [UInt8]? {
        return divideHex(a: a, b: b, modulo: true)
    }
    
    public class func divideHex(a: [UInt8], b:[UInt8], modulo: Bool = false) -> [UInt8]? {
        var result:[UInt8] = []

        let size_a = a.count
        let size_b = b.count
        
        if size_a < size_b {
            return modulo ? a : nil
        }
        
        var start = 0
        var buffer = 0
        var end = size_b
        
        var carry : [UInt8] = []
                
        while true {
            var sub:[UInt8] = []
            
            if start >= a.count {
                break
            }
            
            if carry.count > 0 {
                sub = carry
                carry = []
            }
            
            for i in start..<end {
                sub.append(a[i])
            }
            
            start = end
            
            while true {
                if let subtract = subtractHex(a: sub, b: b) {
                    sub = subtract
                    buffer += 1
                } else {
                    carry = sub
                    break
                }
            }
            
            end += 1
            result.append(UInt8(buffer))
            buffer = 0
        }
        
        if modulo && carry.count == 0{
            return [0]
        }
        
        if result.count == 1 {
            if let first = result.first {
                return modulo ? carry : first == 0 ? nil : result
            }
        }
                
        for int8 in result {
            if int8 == 0 {
                result.removeFirst()
            } else {
                break
            }
        }
        
        return modulo ? carry : result
    }
}
