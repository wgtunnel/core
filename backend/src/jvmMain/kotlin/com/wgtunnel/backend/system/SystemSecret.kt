package com.wgtunnel.backend.system

import com.wgtunnel.backend.loadBackendNativeLibrary
import java.util.Base64

internal object SystemSecretNative {
    @JvmStatic external fun protect(b64: String): String?

    @JvmStatic external fun unprotect(b64: String): String?
}

/**
 * DPAPI encryption for the daemon's account on Windows, so only SYSTEM can read what the daemon
 * stores. Elsewhere [isAvailable] is false and callers rely on file permissions.
 */
object SystemSecret {
    private val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")
    private val available by lazy { isWindows && loadBackendNativeLibrary() }

    val isAvailable: Boolean
        get() = available

    fun protect(data: ByteArray): ByteArray? = transform(data, SystemSecretNative::protect)

    fun unprotect(data: ByteArray): ByteArray? = transform(data, SystemSecretNative::unprotect)

    private fun transform(data: ByteArray, fn: (String) -> String?): ByteArray? {
        if (!available) return null
        val out = runCatching { fn(Base64.getEncoder().encodeToString(data)) }.getOrNull()
        return out?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
    }
}
