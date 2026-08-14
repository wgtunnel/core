package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

object NativeDnsResolver {
    private val log = Logger.withTag("NativeDnsResolver")
    private const val TIMEOUT_MS = 7_000L

    suspend fun resolveHostBootstrap(
        host: String,
        protocol: String,
        resolvedUpstream: String,
        originalUpstream: String,
        bypass: Boolean,
    ): DnsBootstrapResult =
        withContext(Dispatchers.IO) {
            try {
                val raw =
                    withTimeout(TIMEOUT_MS.milliseconds) {
                        resolveBootstrapSync(
                            host,
                            protocol,
                            resolvedUpstream,
                            originalUpstream,
                            if (bypass) 1 else 0,
                        )
                    }
                parseBootstrapResult(raw).also { result ->
                    log.i {
                        "Native resolve host=$host protocol=$protocol bypass=$bypass " +
                            "upstream=${resolvedUpstream.ifBlank { originalUpstream.ifBlank { "(local)" } }} " +
                            "→ v4=${result.ipv4} v6=${result.ipv6}"
                    }
                }
            } catch (e: TimeoutCancellationException) {
                log.e(e) { "DNS bootstrap timed out host=$host protocol=$protocol" }
                throw RuntimeException("DNS bootstrap timed out for $host", e)
            } catch (e: Exception) {
                log.w(e) { "DNS bootstrap failed host=$host protocol=$protocol" }
                throw e
            }
        }

    private fun parseBootstrapResult(raw: String): DnsBootstrapResult {
        if (raw.startsWith("ERR|")) throw RuntimeException(raw.removePrefix("ERR|"))
        val parts = raw.split(";")
        val v4 =
            parts
                .firstOrNull { it.startsWith("v4=") }
                ?.removePrefix("v4=")
                ?.takeIf { it.isNotBlank() }
                ?.split(",") ?: emptyList()
        val v6 =
            parts
                .firstOrNull { it.startsWith("v6=") }
                ?.removePrefix("v6=")
                ?.takeIf { it.isNotBlank() }
                ?.split(",") ?: emptyList()
        return DnsBootstrapResult(ipv4 = v4, ipv6 = v6)
    }

    private external fun resolveBootstrapSync(
        host: String,
        protocol: String,
        resolvedUpstream: String,
        originalUpstream: String,
        bypass: Int,
    ): String
}
