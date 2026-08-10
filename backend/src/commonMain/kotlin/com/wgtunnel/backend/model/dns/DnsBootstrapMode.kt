package com.wgtunnel.backend.model.dns

sealed class DnsBoostrapMode {

    data object System : DnsBoostrapMode()

    data class Custom(val config: DnsBoostrapConfig) : DnsBoostrapMode()
}
