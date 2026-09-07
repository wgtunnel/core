package com.wgtunnel.backend

import co.touchlab.kermit.Logger
import dev.nucleusframework.core.runtime.NativeLibraryLoader

private val log = Logger.withTag("NativeLibrary")

actual fun loadBackendNativeLibrary() {
    val osName = System.getProperty("os.name").lowercase()
    val isWindows = osName.contains("win")

    val sidecars = if (isWindows) listOf("wintun.dll") else emptyList()

    val loaded = NativeLibraryLoader.load(
        libraryName = "wg",
        callerClass = NativeLibraryJvm::class.java,
        resourcePrefix = "/natives",
        sidecarFiles = sidecars
    )

    if (loaded) {
        log.i { "Successfully loaded native backend library" }
    } else {
        log.e { "Failed to load native backend library or unsupported platform" }
    }
}

private object NativeLibraryJvm