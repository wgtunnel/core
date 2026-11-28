package com.wgtunnel.backend.system

import com.wgtunnel.backend.enums.Ipv6Support

expect class NetworkSnapshot {
    val key: String
    /** Null when the monitor could not read the network's link properties. */
    val hasIpv6: Boolean?
    val isUsable: Boolean
    /** Whether the platform verified internet on the network. Always true where it can't tell. */
    val isValidated: Boolean

    fun hasNetwork(): Boolean
}

/** [hasIpv6] is only a real reading on a usable network, anything else is [Ipv6Support.Unknown]. */
internal fun NetworkSnapshot?.ipv6Support(): Ipv6Support {
    if (this == null || !isUsable || !hasNetwork()) return Ipv6Support.Unknown
    return when (hasIpv6) {
        true -> Ipv6Support.Available
        false -> Ipv6Support.Unavailable
        null -> Ipv6Support.Unknown
    }
}
