// swift-tools-version:5.3

import PackageDescription

let package = Package(
  name: "securevault-ios",
  platforms: [
    .iOS(.v15),
  ],
  products: [
    .library(
      name: "securevault-ios",
      type: .static,
      targets: ["securevault-ios"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "securevault-ios",
      dependencies: [
        .byName(name: "Tauri")
      ],
      path: "Sources")
  ]
)
