package com.wgtunnel.backend.model.dns

sealed class DnsBoostrapConfig(open val upstream: String?) {
    abstract val protocol: String

    data class Plain(override val upstream: String?) : DnsBoostrapConfig(upstream) {
        override val protocol: String
            get() = "plain"
    }

    data class DoH(override val upstream: String?) : DnsBoostrapConfig(upstream) {
        override val protocol: String
            get() = "doh"
    }

    data class DoT(override val upstream: String?) : DnsBoostrapConfig(upstream) {
        override val protocol: String
            get() = "dot"
    }
}
