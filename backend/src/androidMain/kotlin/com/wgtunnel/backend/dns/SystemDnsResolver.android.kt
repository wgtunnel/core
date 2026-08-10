package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.system.NetworkMonitor
import java.net.Inet4Address
import java.net.Inet6Address
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

actual class SystemDnsResolver actual constructor(val networkMonitor: NetworkMonitor) :
    PeerResolver {
    private val log = Logger.withTag("SystemDnsResolver")

    override suspend fun resolve(host: String): DnsBootstrapResult =
        withContext(Dispatchers.IO) {
            val network =
                networkMonitor.networkState.value?.network
                    ?: run {
                        log.w { "Failed to get underlay network, returning empty result" }
                        return@withContext DnsBootstrapResult()
                    }
            try {
                val ips =
                    withTimeoutOrNull(DNS_REQUEST_TIMEOUT_SEC.seconds) {
                        network.getAllByName(host).toList()
                    }
                        ?: run {
                            log.w {
                                "Bootstrap timed out after $DNS_REQUEST_TIMEOUT_SEC seconds, returning empty result"
                            }
                            return@withContext DnsBootstrapResult()
                        }
                DnsBootstrapResult(
                    ipv4 = ips.filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress },
                    ipv6 = ips.filterIsInstance<Inet6Address>().mapNotNull { it.hostAddress },
                )
            } catch (_: Exception) {
                DnsBootstrapResult()
            }
        }

    companion object {
        const val DNS_REQUEST_TIMEOUT_SEC = 5
    }
}
