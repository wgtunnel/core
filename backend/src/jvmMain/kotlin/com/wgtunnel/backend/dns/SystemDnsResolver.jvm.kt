package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.system.NetworkMonitor

actual class SystemDnsResolver actual constructor(networkMonitor: NetworkMonitor) : PeerResolver {
    private val log = Logger.withTag("SystemDnsResolver")

    override suspend fun resolve(host: String): DnsBootstrapResult {
        log.i { "Resolving $host via local underlay DNS (bypass mark + physical DNS servers)" }
        return NativeDnsResolver.resolveHostBootstrap(
            host = host,
            protocol = "local",
            resolvedUpstream = "",
            originalUpstream = "",
            bypass = true,
        )
    }
}
