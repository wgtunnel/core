package com.wgtunnel.backend

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.system.DesktopFirewall
import com.wgtunnel.backend.system.DesktopFirewallNative
import dev.nucleusframework.core.runtime.NativeLibraryLoader
import java.util.concurrent.atomic.AtomicBoolean

private val log = Logger.withTag("NativeLibrary")

actual fun loadBackendNativeLibrary(): Boolean {
    val osName = System.getProperty("os.name").lowercase()
    val isWindows = osName.contains("win")

    val sidecars = if (isWindows) listOf("wintun.dll") else emptyList()

    val loaded =
        NativeLibraryLoader.load(
            libraryName = "wg",
            callerClass = NativeLibraryJvm::class.java,
            resourcePrefix = "/natives",
            sidecarFiles = sidecars,
        )

    if (loaded) {
        log.i { "Successfully loaded native backend library" }
        applyInstanceName()
    } else {
        log.e { "Failed to load native backend library or unsupported platform" }
    }
    return loaded
}

private val instanceApplied = AtomicBoolean(false)

// Before anything can create firewall rules, which carry the name.
private fun applyInstanceName() {
    val name =
        System.getProperty(DesktopFirewall.INSTANCE_PROP)?.takeIf { it.isNotBlank() } ?: return
    if (!instanceApplied.compareAndSet(false, true)) return
    if (DesktopFirewallNative.setInstanceName(name) == 0) {
        log.i { "Firewall instance $name" }
    } else {
        log.e { "Failed to set firewall instance $name" }
    }
}

private object NativeLibraryJvm
