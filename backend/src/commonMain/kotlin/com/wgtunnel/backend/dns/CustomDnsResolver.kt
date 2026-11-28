package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.dns.DnsBoostrapConfig
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.util.DnsHostUtils
import com.wgtunnel.backend.util.UrlParse
import java.util.concurrent.ConcurrentHashMap

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
                val freshIps = buildList {
                    addAll(resolutionResult.ipv4)
                    addAll(resolutionResult.ipv6.map { it.removeSurrounding("[", "]") })
                }
                val ips =
                    if (freshIps.isNotEmpty()) {
                        lastUpstreamIps[hostToResolve] = freshIps
                        freshIps
                    } else {
                        lastUpstreamIps[hostToResolve]?.also {
                            log.w { "Custom DNS upstream host did not resolve, using last known IPs" }
                            log.d { "Using last known IPs for ${UrlParse.redactCredentials(upstream)}: $it" }
                        }
                    }
                if (ips.isNullOrEmpty()) {
                    log.w { "Failed to resolve custom DNS upstream host" }
                    log.d { "Failed to resolve custom DNS upstream host: ${UrlParse.redactCredentials(upstream)}" }
                    return DnsBootstrapResult()
                }
                // The configured host stays the TLS name, so the cached IPs are still verified
                ips.map { DnsHostUtils.replaceHostWithIP(upstream, it) }
            } else {
                listOf(upstream)
            }

        log.i { "Custom DNS resolve protocol=${dnsConfig.protocol} bypass=$bypass" }
        log.d {
            "Custom DNS protocol=${dnsConfig.protocol} host=$host " +
                "upstreams=${UrlParse.redactCredentials(resolvedUpstreams.toString())} bypass=$bypass"
        }

        return try {
            NativeDnsResolver.resolveHostBootstrap(
                host = host,
                protocol = dnsConfig.protocol,
                resolvedUpstream = resolvedUpstreams.joinToString(","),
                originalUpstream = upstream,
                bypass = bypass,
            )
        } catch (e: Exception) {
            log.w(e) { "Custom DNS resolution failed protocol=${dnsConfig.protocol}" }
            log.d {
                "Custom DNS resolution failed host=$host " +
                    "upstreams=${UrlParse.redactCredentials(resolvedUpstreams.toString())}"
            }
            DnsBootstrapResult()
        }
    }

    companion object {
        private val lastUpstreamIps = ConcurrentHashMap<String, List<String>>()
    }
}
