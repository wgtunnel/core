# WG Tunnel Core

The shared backend used by the [WG Tunnel](https://wgtunnel.com) apps: WireGuard / AmneziaWG
config parsing, tunnel orchestration, tunnel recovery, DNS bootstrap, and native JNI.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.wgtunnel/backend.svg)](https://central.sonatype.com/search?q=g:com.wgtunnel)

## Modules

| Artifact | Description |
| --- | --- |
| `com.wgtunnel:parser` | WireGuard / AmneziaWG conf parser (JVM) |
| `com.wgtunnel:backend` | Kotlin Multiplatform tunnel backend (pulls the Android or JVM variant) |
| `com.wgtunnel:backend-android` | Android variant of the backend |
| `com.wgtunnel:backend-jvm` | JVM / desktop variant of the backend |
| `com.wgtunnel:backend-android-jni` | AmneziaWG userspace + JNI |
| `com.wgtunnel:hevtunnel` | hev-socks5-tunnel JNI for lockdown / kill switch |

## Requirements

Install these before a source build.

- JDK 21
- Git
- `make`
- Android SDK
- Android NDK
- C toolchain
- MinGW-w64
- On Linux and macOS, `flock`

Go toolchain is downloaded and patched.

## Build

From the repo root:

```bash
./gradlew build
```

Format Kotlin:

```bash
./gradlew format
```

## Using the libraries

```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("com.wgtunnel:parser:<version>")
    implementation("com.wgtunnel:backend:<version>")
    // Android
    implementation("com.wgtunnel:backend-android-jni:<version>")
    implementation("com.wgtunnel:hevtunnel:<version>")
}
```

Replace `<version>` with the latest Maven Central version.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for third-party components (AmneziaWG, hev-socks5-tunnel, Tailscale-derived desktop firewall/router).
