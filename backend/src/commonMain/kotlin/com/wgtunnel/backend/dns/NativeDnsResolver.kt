package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

@OptIn(ExperimentalAtomicApi::class)
internal object NativeDnsResolver {
    private val log = Logger.withTag("NativeDnsResolver")
    private const val TIMEOUT_MS = 7_000L

    private val callbacks = ConcurrentHashMap<Long, (String) -> Unit>()
    private val nextId = AtomicLong(0)

    @JvmStatic
    fun onResolutionComplete(id: Long, result: String) {
        callbacks.remove(id)?.invoke(result)
    }

    suspend fun resolveHostBootstrap(
        host: String,
        protocol: String,
        resolvedUpstream: String,
        originalUpstream: String,
        bypass: Boolean,
    ): DnsBootstrapResult =
        withContext(Dispatchers.IO) {
            val id = nextId.incrementAndFetch()
            try {
                val raw =
                    withTimeout(TIMEOUT_MS.milliseconds) {
                        suspendCancellableCoroutine { cont ->
                            callbacks[id] = { r -> cont.resumeWith(Result.success(r)) }
                            cont.invokeOnCancellation { callbacks.remove(id) }
                            startBootstrapResolution(
                                id,
                                host,
                                protocol,
                                resolvedUpstream,
                                originalUpstream,
                                if (bypass) 1 else 0,
                            )
                        }
                    }
                parseBootstrapResult(raw)
            } catch (e: TimeoutCancellationException) {
                callbacks.remove(id)
                log.e(e) { "DNS bootstrap timed out host=$host" }
                throw RuntimeException("DNS bootstrap timed out for $host", e)
            } catch (e: Exception) {
                callbacks.remove(id)
                log.w(e) { "DNS bootstrap failed host=$host" }
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

    external fun startBootstrapResolution(
        id: Long,
        host: String,
        protocol: String,
        resolvedUpstream: String,
        originalUpstream: String,
        bypass: Int,
    )
}
