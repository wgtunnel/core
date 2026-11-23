package com.wgtunnel.backend.system

import com.wgtunnel.backend.loadBackendNativeLibrary

internal object FileOwnerNative {
    @JvmStatic external fun ownerSid(path: String): String?
}

/** Reads a file's owner SID through the native backend. Windows only. */
object FileOwner {
    private val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")
    private val available by lazy { isWindows && loadBackendNativeLibrary() }

    /** The owning SID of [path], or null if it can't be read or the platform isn't Windows. */
    fun sidOf(path: String): String? {
        if (!available) return null
        return runCatching { FileOwnerNative.ownerSid(path) }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
    }
}
