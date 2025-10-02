// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "tauri-plugin-p256-signer",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "tauri-plugin-p256-signer",
            type: .static,
            targets: ["tauri-plugin-p256-signer"]),
    ],
    dependencies: [
      .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-p256-signer",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources/P256SignerPlugin"
        ),
        .testTarget(
            name: "P256SignerPluginTests",
            dependencies: ["tauri-plugin-p256-signer"],
            path: "Tests/P256SignerPluginTests"
        ),
    ]
)
