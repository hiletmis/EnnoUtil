// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EnnoUtil",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library( name: "EnnoUtil", targets: ["EnnoUtil"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target( name: "EnnoUtil", dependencies: ["Crpytoworks", "Keccak", "Curve25519", "Blake2", "Ed25519", "secp256k1"]),
        .target( name: "Crpytoworks", dependencies: []),
        .target( name: "Keccak", dependencies: []),
        .target( name: "Ed25519", dependencies: ["Curve25519"]),
        .target( name: "Curve25519", dependencies: []),
        .target( name: "secp256k1", dependencies: []),
        .target( name: "Blake2", dependencies: []),
        .testTarget( name: "EnnoUtilTests", dependencies: ["EnnoUtil"]),
    ]
)
