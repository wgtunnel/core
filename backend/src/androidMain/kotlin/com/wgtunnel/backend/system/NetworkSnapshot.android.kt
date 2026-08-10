package com.wgtunnel.backend.system

import android.net.Network

actual data class NetworkSnapshot(
    actual val key: String,
    actual val hasIpv6: Boolean,
    actual val isUsable: Boolean,
    val network: Network?
) {
    actual fun hasNetwork(): Boolean {
        return network != null
    }
}