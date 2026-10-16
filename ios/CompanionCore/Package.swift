// swift-tools-version: 6.1
// The Rust core, built by `just ios-core`: the xcframework holds the static
// library and its C headers, Sources/CompanionCore/generated the Swift side

import PackageDescription

let package = Package(
    name: "CompanionCore",
    platforms: [.iOS("26.0")],
    products: [
        .library(name: "CompanionCore", targets: ["CompanionCore"]),
    ],
    targets: [
        .binaryTarget(name: "companion_core_ffi", path: "companion_core_ffi.xcframework"),
        .target(
            name: "CompanionCore",
            dependencies: ["companion_core_ffi"],
            path: "Sources/CompanionCore",
            // the generated bindings predate Swift 6's concurrency checks
            swiftSettings: [.swiftLanguageMode(.v5)],
            // iroh reads the network interfaces and watches for changes
            linkerSettings: [.linkedFramework("SystemConfiguration")]
        ),
    ]
)
