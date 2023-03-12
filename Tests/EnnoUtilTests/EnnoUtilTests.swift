import XCTest
@testable import EnnoUtil

final class EnnoUtilTests: XCTestCase {
    
    private static let seed = "denial adult elevator below success birth sheriff front acid chef debate start"
    
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(Base58Encoder.decode("39wFF1"), [84, 69, 83, 84])
        XCTAssertEqual(Base58Encoder.decodeToStr("39wFF1"), "TEST")
        XCTAssertEqual(Base58Encoder.encode([84, 69, 83, 84]), "39wFF1")
        XCTAssertEqual(Base58Encoder.validate("39wFF1"), true)
    }
    
    func testBip39Seed() {
        XCTAssertEqual(CryptoUtil.shared.getBip39Seed(seed: EnnoUtilTests.seed, passphrase: ""), "25319dba10231984b2d243b6915ab9d2c1adb96e30fdd5f8ee15c79758e939984ce2cda3a8dc35bcec4dfd9abd129a6e95c809d01225651743919e17d1e932c8")
        
        XCTAssertEqual(CryptoUtil.shared.getRootKey(seed: EnnoUtilTests.seed, passphrase: ""), "ad58258c043e913fcbdf207dfdbf95ffd317192b2cffad0063eb864b7ce31a6e78af8520869c5c349d390bdb3f40387299e88839c4cce5d4aa9a082835aa34fb")
    }
    
    func testRootKey() {
        XCTAssertEqual(CryptoUtil.shared.getB32Root(seed: EnnoUtilTests.seed, passphrase: "", version: VersionBytes.mainnetPrivate), "xprv9s21ZrQH143K3G3gd4fbajvM6CoU7aL1Qk4H8tRkR5g6M9NqUmbvCeoWo23NtnHRdwaa3LySYiBbB48TbrYYnNDBc3AAmpJndeCQdeMxFbz")
    }
    
   func testFingerPrint() {
       XCTAssertEqual(Web3Crypto.getFingerprint(seed: EnnoUtilTests.seed), [115, 93, 68, 69])
   }
    
   func testExtPriv() {
       XCTAssertEqual(Web3Crypto.deriveExtPrivateKey(key: Web3Crypto.getBip32Key(seed: EnnoUtilTests.seed), childNumber: 2147483692), ([]))
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
        XCTAssertEqual(Web3Crypto.Key(privKey: "a912f04788a435a4c01ef7442809af626f9670426e2d1367421c34438af9b7a6"), "0469de4780436611afed73aa8a01b504dc3b23dbaee7da635f74e9677aa8552de029a89a135bcfee832ee3ff2d51fff3b6db5dac247b05cb8f8e871e6694f0a72d")
    }
    
    func testPriv2PublicCompressed() {
        XCTAssertEqual(Web3Crypto.Key(privKey: "ad58258c043e913fcbdf207dfdbf95ffd317192b2cffad0063eb864b7ce31a6e", compressed: true), "028c5922309fed7cdd144ecd8269ad6aa9a06a3f5dbfafb267f409a0530b850c0d")
    }
    
    func testWeb3Address() {
        XCTAssertEqual(Web3Crypto.Address(publicKey: "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39").lowercased(), "90F8bf6A479f320ead074411a4B0e7944Ea8c9C1".lowercased())
        
        XCTAssertEqual(Web3Crypto.Address(privateKey: "638a8089747e8d14d4cdcca0f512471741c2993e5e85c51a496f0d063e43631e").lowercased(), "9dE86784F52894980bD7a1789e0931aFF3Adc9Ce".lowercased())
    }
    
    func testExtKey() {
        
    }
    
}


