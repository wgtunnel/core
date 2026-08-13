package com.wgtunnel.backend

import co.touchlab.kermit.Logger
import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean

private val loaded = AtomicBoolean(false)
private val log = Logger.withTag("NativeLibrary")

actual fun loadBackendNativeLibrary() {
    if (!loaded.compareAndSet(false, true)) return

    val osName = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()

    val (osDir, libFileName) =
        when {
            osName.contains("win") -> {
                val archDir =
                    when {
                        arch.contains("aarch64") || arch.contains("arm64") -> "windows-aarch64"
                        else -> "windows-x86_64"
                    }
                archDir to "libwg.dll"
            }
            osName.contains("mac") || osName.contains("darwin") -> {
                val archDir =
                    when {
                        arch.contains("aarch64") || arch.contains("arm64") -> "darwin-aarch64"
                        else -> "darwin-x86_64"
                    }
                archDir to "libwg.dylib"
            }
            else -> {
                val archDir =
                    when {
                        arch.contains("aarch64") || arch.contains("arm64") -> "linux-aarch64"
                        else -> "linux-x86_64"
                    }
                archDir to "libwg.so"
            }
        }

    val resourcePath = "natives/$osDir/$libFileName"
    val stream =
        Thread.currentThread().contextClassLoader.getResourceAsStream(resourcePath)
            ?: NativeLibraryJvm::class.java.classLoader.getResourceAsStream(resourcePath)
            ?: error("Native library not found on classpath: $resourcePath")

    val tempDir = Files.createTempDirectory("wgtunnel-native-").toFile().also { it.deleteOnExit() }
    val outFile = File(tempDir, libFileName)
    stream.use { input -> outFile.outputStream().use { input.copyTo(it) } }
    outFile.deleteOnExit()

    log.i { "Loading native backend library from ${outFile.absolutePath}" }
    System.load(outFile.absolutePath)
}

private object NativeLibraryJvm
