package com.wgtunnel.backend.dns

import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.system.NetworkMonitor

interface PeerResolver {
    suspend fun resolve(host: String): DnsBootstrapResult
}

expect class SystemDnsResolver(networkMonitor: NetworkMonitor) : PeerResolver
