import XCTest
@testable import EnnoUtil

final class WavesUtilTests: XCTestCase {
    
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
        XCTAssertEqual(CryptoUtil.shared.getBip39Seed(seed: WavesUtilTests.seed, passphrase: ""), "25319dba10231984b2d243b6915ab9d2c1adb96e30fdd5f8ee15c79758e939984ce2cda3a8dc35bcec4dfd9abd129a6e95c809d01225651743919e17d1e932c8")
        
        XCTAssertEqual(CryptoUtil.shared.getRootKey(seed: WavesUtilTests.seed, passphrase: ""), "ad58258c043e913fcbdf207dfdbf95ffd317192b2cffad0063eb864b7ce31a6e78af8520869c5c349d390bdb3f40387299e88839c4cce5d4aa9a082835aa34fb")
    }
    
    func testRootKey() {
        XCTAssertEqual(CryptoUtil.shared.getB32Root(seed: WavesUtilTests.seed, passphrase: "", version: VersionBytes.mainnetPrivate), "xprv9s21ZrQH143K3G3gd4fbajvM6CoU7aL1Qk4H8tRkR5g6M9NqUmbvCeoWo23NtnHRdwaa3LySYiBbB48TbrYYnNDBc3AAmpJndeCQdeMxFbz")
    }
}
