package com.wgtunnel.backend.system

actual data class NetworkSnapshot(
    actual val key: String,
    actual val hasIpv6: Boolean?,
    actual val isUsable: Boolean,
    // TODO: report real connectivity (Windows NLM, macOS NWPath, NetworkManager) so recovery can
    //  retry as soon as internet comes back, like on Android
    actual val isValidated: Boolean = true,
) {
    actual fun hasNetwork(): Boolean = isUsable
}
