// swift-tools-version:5.9
// eID Mongolia — client-side PAdES (PDF гарын үсэг локалд; PDF eID сервер рүү явахгүй).
// Гуравдагч хамааралгүй: CryptoKit, Security.framework, системийн zlib.
import PackageDescription

let package = Package(
    name: "GeregeEIDPades",
    platforms: [.iOS(.v14), .macOS(.v13)],
    products: [
        .library(name: "GeregeEIDPades", targets: ["GeregeEIDPades"])
    ],
    targets: [
        // Verify-page fonts (pre-subset NotoSans, fixed FlateDecode bytes = Go reference pades/assets; OFL).
        .target(name: "GeregeEIDPades", resources: [.copy("Resources/fonts")]),
        // Go reference (eid-mongolia-sdk-go pades/testdata/golden) — scripts/sync-pades-golden.sh-ээр vendor хийсэн.
        .testTarget(name: "GeregeEIDPadesTests", dependencies: ["GeregeEIDPades"],
                    exclude: ["golden"])
    ]
)
