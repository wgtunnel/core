package com.wgtunnel.backend.dns

import android.net.Network
import androidx.annotation.Keep
import co.touchlab.kermit.Logger
import java.net.Inet4Address
import java.net.Inet6Address
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

@OptIn(ExperimentalAtomicApi::class)
@Keep
internal object UnderlayDnsBridge {
    private val log = Logger.withTag("UnderlayDnsBridge")
    private val underlayNetworkHandle = AtomicLong(0L)

    @OptIn(ExperimentalAtomicApi::class)
    private val underlayNetwork = AtomicReference<Network?>(null)

    @JvmStatic
    private external fun setUnderlayNetworkHandleNative(handle: Long)

    fun setUnderlayNetwork(network: Network?) {
        underlayNetwork.store(network)
        val handle = network?.networkHandle ?: 0L
        val previous = underlayNetworkHandle.exchange(handle)
        if (previous != handle) {
            setUnderlayNetworkHandleNative(handle)
            log.d { "Underlay network handle $previous to $handle" }
        }
    }

    @Keep
    @JvmStatic
    fun lookupOnUnderlayNetwork(host: String, networkFamily: String): String {
        val network = underlayNetwork.load() ?: run {
            log.w { "lookupOnUnderlayNetwork: no underlay for $host" }
            return ""
        }
        return try {
            val addrs = network.getAllByName(host)
            val filtered =
                when (networkFamily) {
                    "ip4" -> addrs.filterIsInstance<Inet4Address>()
                    "ip6" -> addrs.filterIsInstance<Inet6Address>()
                    else -> addrs.toList()
                }
            filtered.mapNotNull { it.hostAddress }.joinToString("\n")
        } catch (e: Exception) {
            log.e(e) { "lookupOnUnderlayNetwork failed for $host" }
            ""
        }
    }
}