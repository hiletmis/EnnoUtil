import XCTest
@testable import WavesUtil

final class WavesUtilTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(Base58Encoder.decode("39wFF1"), [84, 69, 83, 84])
        XCTAssertEqual(Base58Encoder.decodeToStr("39wFF1"), "TEST")
        XCTAssertEqual(Base58Encoder.encode([84, 69, 83, 84]), "39wFF1")
        XCTAssertEqual(Base58Encoder.validate("39wFF1"), true)
        
    }
}
