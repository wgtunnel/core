package com.wgtunnel.backend.model.network

data class InetNetwork(
    val hostAddress: String,
    val prefixLength: Int,
) {
    val isIpv4: Boolean
        get() = ':' !in hostAddress

    val isIpv6: Boolean
        get() = ':' in hostAddress
}
