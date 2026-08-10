package com.wgtunnel.backend.system

actual data class NetworkSnapshot(
    actual val key: String,
    actual val hasIpv6: Boolean,
    actual val isUsable: Boolean
) {
    // TODO
    actual fun hasNetwork(): Boolean {
        return true
    }
}