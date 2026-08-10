package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.dns.DnsBoostrapConfig
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.util.DnsHostUtils

/** Upstream resolved by system, then native DoH/DoT/plain via native. */
class CustomDnsResolver(
    private val dnsConfig: DnsBoostrapConfig,
    private val bypass: Boolean,
    private val systemDns: SystemDnsResolver,
) : PeerResolver {

    private val log = Logger.withTag("CustomDnsResolver")

    override suspend fun resolve(host: String): DnsBootstrapResult {
        val upstream = dnsConfig.upstream?.trim().orEmpty()
        if (upstream.isEmpty()) {
            log.w { "Custom DNS mode selected but no upstream configured" }
            return DnsBootstrapResult()
        }

        val resolvedUpstreams: List<String> =
            if (DnsHostUtils.needsResolution(upstream)) {
                log.d { "Upstream DNS needs resolution, resolving via system resolver" }
                val hostToResolve = DnsHostUtils.extractHost(upstream)
                val resolutionResult = systemDns.resolve(hostToResolve)
                val ips = buildList {
                    addAll(resolutionResult.ipv4)
                    addAll(resolutionResult.ipv6.map { it.removeSurrounding("[", "]") })
                }
                if (ips.isEmpty()) {
                    log.w { "Failed to resolve custom DNS upstream host: $upstream" }
                    return DnsBootstrapResult()
                }
                ips.map { DnsHostUtils.replaceHostWithIP(upstream, it) }
            } else {
                listOf(upstream)
            }

        log.d { "Using custom resolver with resolved upstreams $resolvedUpstreams" }

        return try {
            NativeDnsResolver.resolveHostBootstrap(
                host = host,
                protocol = dnsConfig.protocol,
                resolvedUpstream = resolvedUpstreams.joinToString(","),
                originalUpstream = upstream,
                bypass = bypass,
            )
        } catch (e: Exception) {
            log.w(e) { "Custom DNS resolution failed for host=$host upstreams=$resolvedUpstreams" }
            DnsBootstrapResult()
        }
    }
}
