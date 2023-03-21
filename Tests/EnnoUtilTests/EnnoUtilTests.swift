import XCTest
@testable import EnnoUtil

final class EnnoUtilTests: XCTestCase {
    
    private static let seed = "denial adult elevator below success birth sheriff front acid chef debate start"
    private static let path = "m/44'/60'/0'/0/0"
    private static let accountPath = "m/44'/60'/0'"

   func testFingerPrint() {
       XCTAssertEqual(Web3Crypto.getFingerprint(seed: EnnoUtilTests.seed), [115, 93, 68, 69])
   }
    
    func testWeb3Account() {
        let seed = EnnoUtilTests.seed
        let path = EnnoUtilTests.path
        
        let address = "0x4344Eb02Dd0275B724B988AF97758edeaD63cFEa".lowercased()
        let pubKey = "0x0469de4780436611afed73aa8a01b504dc3b23dbaee7da635f74e9677aa8552de029a89a135bcfee832ee3ff2d51fff3b6db5dac247b05cb8f8e871e6694f0a72d".lowercased()
        let privKey = "0xa912f04788a435a4c01ef7442809af626f9670426e2d1367421c34438af9b7a6".lowercased()

        let account = CryptoUtil.shared.web3Account(seed: seed, path: path)
        
        let isAddress = account?.address == address
        let isPubKey = account?.publicKey == pubKey
        let isPrivKry = account?.privateKey == privKey
        
        XCTAssertTrue(isAddress && isPubKey && isPrivKry)
    }
    
    func testXprivXpub() {
        let xPriv = "xprv9s21ZrQH143K3G3gd4fbajvM6CoU7aL1Qk4H8tRkR5g6M9NqUmbvCeoWo23NtnHRdwaa3LySYiBbB48TbrYYnNDBc3AAmpJndeCQdeMxFbz"
        let xPub = ""
        if let xPrv = CryptoUtil.shared.web3xPrv(seed: EnnoUtilTests.seed, path: "m/") {
            let xAccountDepth = Web3Crypto.deriveExtKey(xPrv: xPrv, index: 0)

            print(xPrv)
            
        }
        
    }
    
    func testAccountXprv() {

        let key1 = "xprv9ykwE8ef1StdEYpYNzd7UAu1vmeakgpDSV99uh6f3AZkfM3ZQv1mtATiGnH3APrTy4sLDXXvoBxJYRDBKLUMektKfVkLcDVWkSEWUBfd1rh"
        let key2 = "xprvA2Lvvd3bSaqeQ7QUHNhyWDMTxPzAoCkbwqMUBGKunxZH8zSgtNaNnsymvHC5LArmV1a8RYWwZASDjhPLEv7QVMSGuo595e7MV1WzAKM293q"

        if let xPrv = CryptoUtil.shared.web3xPrv(seed: EnnoUtilTests.seed, path: EnnoUtilTests.accountPath) {
            XCTAssertEqual(xPrv.lowercased(), key1.lowercased())
            let xNextDepth = Web3Crypto.deriveExtKey(xPrv: xPrv, index: 0)
            XCTAssertEqual(Base58Encoder.encode(xNextDepth!).lowercased(), key2.lowercased())
            
            let address1 = CryptoUtil.shared.web3address(xPriv: Base58Encoder.encode(xNextDepth!), depth: 4, index: 0)
            XCTAssertEqual(address1, "0x4344Eb02Dd0275B724B988AF97758edeaD63cFEa".lowercased())
            let address2 = CryptoUtil.shared.web3address(xPriv: Base58Encoder.encode(xNextDepth!), depth: 4, index: 1)
            XCTAssertEqual(address2, "0xA00e35E792f4C573179323A4B1283C91539a8055".lowercased())
            let address3 = CryptoUtil.shared.web3address(xPriv: Base58Encoder.encode(xNextDepth!), depth: 4, index: 2)
            XCTAssertEqual(address3, "0x234d29f991d6d402F4fd0f7E1B0512b00B185345".lowercased())
            let address4 = CryptoUtil.shared.web3address(xPriv: Base58Encoder.encode(xNextDepth!), depth: 4, index: 3)
            XCTAssertEqual(address4, "0x4B6Cb8d108cEE7fb93Eb373d73AC4AFcdc979595".lowercased())
            let address5 = CryptoUtil.shared.web3address(xPriv: Base58Encoder.encode(xNextDepth!), depth: 4, index: 4)
            XCTAssertEqual(address5, "0xd7Ed609F6E3924ba00E9Ed92F8d4ebAD4Eff23c7".lowercased())
        }
    }
    
    func testChecksum() {
        let encode = Base58Encoder.encode(Web3Crypto.checksum(datas: [1,1,1,1,1,1,1,1,1]))
        let validate = Web3Crypto.validateChecksum(datas: Base58Encoder.decode(encode))
        XCTAssertEqual(validate, [1,1,1,1,1,1,1,1,1])
    }
    
    func testP2PSH() {
        
        let pubkeys = [
            "033d146cd81f3cca87ec904028d0da552cc95e70f6535a791c1395fb9c32d25d2a",
            "03c057aa44caa975b9c04fe0d6e5af7d396382772bfc1c7e0a4f05dac141f30e3a",
            "0302f39f628ff478988443d1aff1c8ddd2e532ce628a4517caf106787b2b1a955e",
            "031818cb38cb8c58ce9d93141fb7757f1bd2cb9956a631fcfd0baead1bd24b01d3"
        ]
        
        let addresses = [
            "3FFxkR6MJVfc91D2vTikdPyWBA9TzSp9ei",
            "3NGjTMvdFkHkQunmyLUo2oqHSRyoRoxLSZ",
            "3NA18PGcWLDvr9JzAuLWXA6DyeyQro4pzm",
            "38HqrD57DcqBqP1bY6Qk9wbEyify4CPRBJ"
        ]
        
        for (index, pubkey) in pubkeys.enumerated() {
            let key0 = Web3Crypto.p2pshAddress( pubKey: pubkey.hexToBytes(), hrp: "")
            XCTAssertEqual(key0, addresses[index])
        }

    }
    
    func testP2PKH() {
        let key = Web3Crypto.p2pkhAddress(
            privKey: "30fa9a0e4db9bc1773e8a2afd8310e47d5f596965c6bef34468360b32df55b78".hexToBytes(),
            hrp: "")
        XCTAssertEqual(key, "1E8FqVzE6Er4XrroBVxxbfjUHx7bE94juJ")
        let key2 = Web3Crypto.p2pkhAddress(
            pubKey: "031db82dd04f27ae5ffd90ccbd1474d0657bce8879458767f28bd6c2724743c0d5".hexToBytes(),
            hrp: "")
        XCTAssertEqual(key2, "1DA5tQmfYJDKZ7oG1HRMkyS2t5hEn9tMew")
        let key3 = Web3Crypto.p2pkhAddress(
            privKey: "0b52b5d35c842a3d5f21d5a2128705740150ea74a68b70d62e28c3cb129e380a".hexToBytes(),
            hrp: "",
            compressed: true)
        XCTAssertEqual(key3, "15yemm2ZPWKzTeu1JLnVWMotp9R2oFVX37")
    }
    
    func testBtcP2PSHAddress() {
        let btcPath = "m/49\'/0\'/0\'"
        if let xPrv = CryptoUtil.shared.web3xPrv(seed: EnnoUtilTests.seed, path: btcPath) {
            let xAccountDepth = Web3Crypto.deriveExtKey(xPrv: xPrv, index: 0)

            let array = [
                "3MwEmpTo5JXLABsUwPtmvygc2BPxvk7rGM",
                "36y7HXRuFymTnqruLE6h9wXu1BKcpcCLP1",
                "3QAf8CKLjdmNUmiMJwwxeu17BMeQEfY92c",
                "3HEFbBjDbHW5akhY6gx4vjkYscrntdWPW4",
                "3DMcPrykieHP1dgEWALxi3B3uZn841qVzY",
                "3Hq5MR136uEzK9LboE4kYyauhVEyBC5qAu",
                "3MC9EZgR6JRwg8bjyBWXLS7NUxpeG4Wwxs",
                "32Vb8QhoEhYXnLTF6AUdzbRmL4XnmYNRrG",
                "3JqCV9RNmZnPLY4XHUuGLcZw3nff6NmTyP",
                "34muaPyFe2as934Uym7JQfpJjXppxfSn5e",
                "3A423eS5U2RofBiLxxMJMTmunsRQgZCUbZ",
            ]
            
            for i in 0..<10 {
                let xAddressDepth = Web3Crypto.deriveExtKey(xPrv: Base58Encoder.encode(xAccountDepth!), index: i)
                let privKey:[UInt8] = Array(xAddressDepth![46...77])

                let address = Web3Crypto.p2pshAddress(privKey: privKey, hrp: "", compressed: true)
                XCTAssertEqual(address, array[i])
            }
        }
    }
    
    func testBtcAddress() {
        let btcPath = "m/44\'/0\'/0\'"
        if let xPrv = CryptoUtil.shared.web3xPrv(seed: EnnoUtilTests.seed, path: btcPath) {
            let xAccountDepth = Web3Crypto.deriveExtKey(xPrv: xPrv, index: 0)

            let array = [
                "1EMTwcC2SXBgR1wCK91KP5ge7xMwnizTdr",
                "1DA5tQmfYJDKZ7oG1HRMkyS2t5hEn9tMew",
                "15yemm2ZPWKzTeu1JLnVWMotp9R2oFVX37",
                "12vkAqwe6AF5PYNHB7ADi8MKoy9NTLJcyr",
                "1KkxzsPF6eGViMnXenm6tPxf99SSA8g6CW",
                "1CZXZFyb7eqvX7HRRJPN6FB5HzNaexL2tW",
                "122wBwnVwGMvXYgSxw4UpDe2CE23SwxqJE",
                "1KnGT4NnJixuDbDZ5zMFyQTJvkzDDrkYi9",
                "1EV27SH2fK8uVAZsyd8S1gqh1vwoxozGjG",
                "123ooXUBv5uujvzwmtHHpjhKacBwdzrasa",
                "1JYLcRKb16bbb7b3sHndsUy2mLZeQogzmt",
            ]
            
            for i in 0..<10 {
                let xAddressDepth = Web3Crypto.deriveExtKey(xPrv: Base58Encoder.encode(xAccountDepth!), index: i)
                let privKey:[UInt8] = Array(xAddressDepth![46...77])

                let address = Web3Crypto.p2pkhAddress(privKey: privKey, hrp: "", compressed: true)
                XCTAssertEqual(address, array[i])
            }
        }
    }
    
    func testAvaxAddress() {
        let avaxPath = "m/44\'/9000\'/0\'"
        if let xPrv = CryptoUtil.shared.web3xPrv(seed: EnnoUtilTests.seed, path: avaxPath) {
            
            let xAccountDepth = Web3Crypto.deriveExtKey(xPrv: xPrv, index: 0)
            
            let array = [
                "avax1fukjhvzlrvyu3dhv42yqzhjnrz4kvdm38q8p6x",
                "avax1nndxw2rh7za7vyd042uq2ftnt4q9deqcsv59zr",
                "avax12z60caanh7l89tml9yd9398azggvq776ey4h32",
                "avax12fk0uekw90rttd37fn0tepp7r0qy4zhxaf52v3",
                "avax1evqyaq0hpsvcvhsqe0egg3h5xnywx4hfp362yq",
                "avax1vwgl34qxwv4kd4y763evtytrr3ved757azkc5y",
                "avax1l0cdgnyt2utlhlvcwdwrtz9z4yaqq6m9kmzk8u",
                "avax1sy6m8y2ut5mxnvw4t0fl4fvrwwts0prh2mzc8x",
                "avax1p2408ckd7srcju3gmsjcswmg2h6vf53vh0maq9",
                "avax19gh89phjlaa3hcpvewlmd8hfxx29jc33w7fdrs",
                "avax1f9nxe332q7f50w970q4vjvrll9mxmmw8vtm6xw",
            ]
            
            for i in 0..<10 {
                let xAddressDepth = Web3Crypto.deriveExtKey(xPrv: Base58Encoder.encode(xAccountDepth!), index: i)
                let privKey:[UInt8] = Array(xAddressDepth![46...77])

                let address = Web3Crypto.bech32Address(privKey: privKey, hrp: "avax")
                XCTAssertEqual(address, array[i])
            }
        }
    }
     
    func testAvaxAddressFromXPub() {
        let avaxPath = "m/44\'/9000\'/0\'"
        if let xPriv = CryptoUtil.shared.web3xPrv(seed: EnnoUtilTests.seed, path: avaxPath) {
            let xAccountDepth = Web3Crypto.deriveExtKey(xPrv: xPriv, index: 0)
            print(Base58Encoder.encode(xAccountDepth!))
            
            
        }
        
        if let xPub = CryptoUtil.shared.web3xPub(seed: EnnoUtilTests.seed, path: avaxPath) {
            
            let xAccountDepth = Web3Crypto.derivePublicKey(xPub: xPub, index: 0)
            print(Base58Encoder.encode(xAccountDepth!))


            let array = [
                "avax1fukjhvzlrvyu3dhv42yqzhjnrz4kvdm38q8p6x",
                "avax1nndxw2rh7za7vyd042uq2ftnt4q9deqcsv59zr",
                "avax12z60caanh7l89tml9yd9398azggvq776ey4h32",
                "avax12fk0uekw90rttd37fn0tepp7r0qy4zhxaf52v3",
                "avax1evqyaq0hpsvcvhsqe0egg3h5xnywx4hfp362yq",
                "avax1vwgl34qxwv4kd4y763evtytrr3ved757azkc5y",
                "avax1l0cdgnyt2utlhlvcwdwrtz9z4yaqq6m9kmzk8u",
                "avax1sy6m8y2ut5mxnvw4t0fl4fvrwwts0prh2mzc8x",
                "avax1p2408ckd7srcju3gmsjcswmg2h6vf53vh0maq9",
                "avax19gh89phjlaa3hcpvewlmd8hfxx29jc33w7fdrs",
                "avax1f9nxe332q7f50w970q4vjvrll9mxmmw8vtm6xw",
            ]
            
            for i in 0..<10 {
                let xAddressDepth = Web3Crypto.deriveExtKey(xPrv: Base58Encoder.encode(xAccountDepth!), index: i)
                let privKey:[UInt8] = Array(xAddressDepth![46...77])

                let address = Web3Crypto.bech32Address(privKey: privKey, hrp: "avax")
                XCTAssertNotEqual(address, array[i])
            }
        }
    }
    
    func testEncodeSegwit() {
        let address = Web3Crypto.encodeSegwit(hrp: "avax", addr: "avax1fukjhvzlrvyu3dhv42yqzhjnrz4kvdm38q8p6x")
        XCTAssertEqual(address, "4f2d2bb05f1b09c8b6ecaa88015e5318ab663771".hexToBytes())
    }
    
    func testTypeData() {
        let signature = Web3Crypto.encodeTyped(messageJson: "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],\"Person\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"wallet\",\"type\":\"address\"}],\"Mail\":[{\"name\":\"from\",\"type\":\"Person\"},{\"name\":\"to\",\"type\":\"Person\"},{\"name\":\"contents\",\"type\":\"string\"}]},\"primaryType\":\"Mail\",\"domain\":{\"name\":\"Ether Mail\",\"version\":\"1\",\"chainId\":1,\"verifyingContract\":\"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC\"},\"message\":{\"from\":{\"name\":\"Cow\",\"wallet\":\"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826\"},\"to\":{\"name\":\"Bob\",\"wallet\":\"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB\"},\"contents\":\"Hello, Bob!\"}}")
        XCTAssertEqual(signature?.bytes, "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2".hexToBytes())
    }
    
   func testGetWeb3Address() {
       XCTAssertEqual(CryptoUtil.shared.web3address(seed: EnnoUtilTests.seed, path: EnnoUtilTests.path)?.lowercased(), "0x4344Eb02Dd0275B724B988AF97758edeaD63cFEa".lowercased())
   }
    
    func testDerive() {
        XCTAssertEqual(Web3Crypto.deriveAddress(path: "m/44/60/0/0/0", key: Web3Crypto.getBip32Key(seed: EnnoUtilTests.seed)), "0x92F7Be306AbF6170A5B0990B2f98Bc465Fa1925B".hexToBytes())
        
        XCTAssertEqual(Web3Crypto.deriveAddress(path: "m/44'/60'/0'/0/0", key: Web3Crypto.getBip32Key(seed: "endorse kite retreat stay thank shed struggle jaguar popular demise grid opera someone record basket laptop school remind jump clump mystery dirt chimney about")), "0xC3b86c8AaBF8208C339A63B6fb7402537089085e".hexToBytes())
        
        XCTAssertEqual(Web3Crypto.deriveAddress(path: "m/44'/60'/0'/0/0", key: Web3Crypto.getBip32Key(seed: EnnoUtilTests.seed)), "0x4344Eb02Dd0275B724B988AF97758edeaD63cFEa".hexToBytes())
        
        XCTAssertEqual(Web3Crypto.deriveAddress(path: "m/44'/60'/0'/0/0", key: Web3Crypto.getBip32Key(seed: "distance where slush wave baby vapor blush kiwi canoe decrease sheriff seed")), "0x9d53Fa5481c30663BcBFeB725fcC5268a8D664ad".hexToBytes())
        
        XCTAssertEqual(Web3Crypto.deriveAddress(path: "m/44'/60k'/0'/0/0", key: Web3Crypto.getBip32Key(seed: "eyebrow myth make situate keen verify evolve odor surprise basic capable silk kid critic filter congress hand deer push act weather patient swap follow")), nil)
        
        XCTAssertEqual(Web3Crypto.deriveAddress(path: "m/44'/60'/0'/0/0", key: Web3Crypto.getBip32Key(seed: "eyebrow myth make situate keen verify evolve odor surprise basic capable silk kid critic filter congress hand deer push act weather patient swap follow")), "0x2A2EA0930232966f5236A7C64a1BC8c0B041a9A0".hexToBytes())

    }
    func testAddBigInt() {
        XCTAssertEqual(HexUtil.addHex(a: "3f", b: "aaef"), "ab2e".hexToBytes())
        XCTAssertEqual(HexUtil.addHex(a: "da3f", b: "aaef"), "01852e".hexToBytes())
        XCTAssertEqual(HexUtil.addHex(a: "FFFF", b: "aaaa"), "01aaa9".hexToBytes())
        XCTAssertEqual(HexUtil.addHex(a: "ffffffffffffffffffffffffffffffffffffffffff", b: "ffffffffffffffffffffffffffffffffffffffffff"), "01fffffffffffffffffffffffffffffffffffffffffe".hexToBytes())
    }
    
    func testMultipylyHex() {
        XCTAssertEqual(HexUtil.multiplyHex(a: "02".hexToBytes(), b: "04".hexToBytes()), "08".hexToBytes())
        XCTAssertEqual(HexUtil.multiplyHex(a: "0f".hexToBytes(), b: "ff".hexToBytes()), "0ef1".hexToBytes())
        XCTAssertEqual(HexUtil.multiplyHex(a: "0f".hexToBytes(), b: "01ff".hexToBytes()), "1df1".hexToBytes())
        XCTAssertEqual(HexUtil.multiplyHex(a: "F23F32F23D23".hexToBytes(), b: "0F22F2F2F2".hexToBytes()), "0e52c64698A81097DEE116".hexToBytes())
        XCTAssertEqual(HexUtil.multiplyHex(a: "6C2ea434Be6Ba7B56b62AeE27A574e4b39f5dabf".hexToBytes(), b: "6C2ea434Be6Ba7B56b62AeE27A574e4b39f5dabf".hexToBytes()), "2db7630becf2e309300e6886ebb34cf35166bf0c047322c4d7ce3d2fb1ff84418e4bf76f7a7fda81".hexToBytes())
    }
    
    func testSubtractBigInt() {
        XCTAssertEqual(HexUtil.subtractHex(a: "01000000000003", b: "04"), "FFFFFFFFFFFF".hexToBytes())
        XCTAssertEqual(HexUtil.subtractHex(a: "0102", b: "0003"), "ff".hexToBytes())
        XCTAssertEqual(HexUtil.subtractHex(a: "0003", b: "0102"), nil)
    }
    
    func testDivideHex() {
        XCTAssertEqual(HexUtil.divideHex(a: "FF00FF".hexToBytes(), b: "FF".hexToBytes()), "010001".hexToBytes())
        XCTAssertEqual(HexUtil.divideHex(a: "FF00FF".hexToBytes(), b: "FF".hexToBytes()), "010001".hexToBytes())
    }
    
    func testModuloHex() {
        
        XCTAssertEqual(HexUtil.modulo(a: "0xf90869e33b0c5faafa38f163a5d67a40bda0778019d6c153e76b7c69d5a52222".hexToBytes(),
                              b: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".hexToBytes()),
               "0xf90869e33b0c5faafa38f163a5d67a40bda0778019d6c153e76b7c69d5a52222".hexToBytes())
        
        XCTAssertEqual(HexUtil.modulo(a: "0x1b89f63064d555caabca053fa3afbff7e40eec0c50bd5176a32d56a08fa135510".hexToBytes(),
                                      b: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".hexToBytes()),
                       "0xb89f63064d555caabca053fa3afbff7f863fe3de5c8c772e73030b7c29dd13cf".hexToBytes())
     
        XCTAssertEqual(HexUtil.modulo(a: "0xde6906dac5c8469112195ae977c8bd87aeca53a5c6c0a9e8c39d31506b5f27cf".hexToBytes(),
                                      b: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".hexToBytes()),
                       "0xde6906dac5c8469112195ae977c8bd87aeca53a5c6c0a9e8c39d31506b5f27cf".hexToBytes())
        
        XCTAssertEqual(HexUtil.modulo(a: "0x1304d3b99bd8c4ab020eadca002586db38d0c43d8ef2c4c26a44822200e21d10d".hexToBytes(),
                                      b: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".hexToBytes()),
                       "0x304d3b99bd8c4ab020eadca002586db4d25d66f23fe3abeae475c3933deb8fcc".hexToBytes())
                
        XCTAssertEqual(HexUtil.modulo(a: "0xa912f04788a435a4c01ef7442809af626f9670426e2d1367421c34438af9b7a6".hexToBytes(),
                                      b: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".hexToBytes()),
                       "0xa912f04788a435a4c01ef7442809af626f9670426e2d1367421c34438af9b7a6".hexToBytes())
                
    }
   
    func testPriv2PublicUncompressed() {
        XCTAssertEqual(Web3Crypto.PublicKey(privKey: "a912f04788a435a4c01ef7442809af626f9670426e2d1367421c34438af9b7a6"), "0469de4780436611afed73aa8a01b504dc3b23dbaee7da635f74e9677aa8552de029a89a135bcfee832ee3ff2d51fff3b6db5dac247b05cb8f8e871e6694f0a72d")
    }
    
    func testPriv2PublicCompressed() {
        XCTAssertEqual(Web3Crypto.PublicKey(privKey: "ad58258c043e913fcbdf207dfdbf95ffd317192b2cffad0063eb864b7ce31a6e", compressed: true), "028c5922309fed7cdd144ecd8269ad6aa9a06a3f5dbfafb267f409a0530b850c0d")
    }
    
    func testWeb3Address() {
        XCTAssertEqual(Web3Crypto.Address(privateKey: "dcd0028e22ded7a49dc7a0f5fe586301909896cb9d1039a3d59d299dec00f090").lowercased(), "514E93bFc5a3fE50e1C9C3A082D06975da73F234".lowercased())
        
        XCTAssertEqual(Web3Crypto.Address(publicKey: "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39").lowercased(), "90F8bf6A479f320ead074411a4B0e7944Ea8c9C1".lowercased())
        
        XCTAssertEqual(Web3Crypto.Address(privateKey: "638a8089747e8d14d4cdcca0f512471741c2993e5e85c51a496f0d063e43631e").lowercased(), "9dE86784F52894980bD7a1789e0931aFF3Adc9Ce".lowercased())
    }
    
    func testExtKey() {
        
    }
    
}


