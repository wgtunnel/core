package com.wgtunnel.backend.dns

import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.system.NetworkMonitor

actual class SystemDnsResolver actual constructor(networkMonitor: NetworkMonitor) : PeerResolver {
    override suspend fun resolve(host: String): DnsBootstrapResult =
        NativeDnsResolver.resolveHostBootstrap(
            host = host,
            protocol = "local",
            resolvedUpstream = "",
            originalUpstream = "",
            bypass = true,
        )
}