package com.wgtunnel.backend.dns

import android.net.Network
import co.touchlab.kermit.Logger
import java.net.Inet4Address
import java.net.Inet6Address
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

@OptIn(ExperimentalAtomicApi::class)
internal object UnderlayDnsBridge {
    private val log = Logger.withTag("UnderlayDnsBridge")
    private val underlayNetworkHandle = AtomicLong(0L)
    private val vpnNetworkHandle = AtomicLong(0L)

    @OptIn(ExperimentalAtomicApi::class)
    private val underlayNetwork = AtomicReference<Network?>(null)

    @JvmStatic private external fun setUnderlayNetworkHandleNative(handle: Long)

    @JvmStatic private external fun setVpnNetworkHandleNative(handle: Long)

    fun setUnderlayNetwork(network: Network?) {
        underlayNetwork.store(network)
        val handle = network?.networkHandle ?: 0L
        val previous = underlayNetworkHandle.exchange(handle)
        if (previous != handle) {
            setUnderlayNetworkHandleNative(handle)
            log.d { "Underlay network handle $previous to $handle" }
        }
    }

    fun setVpnNetwork(network: Network?) {
        val handle = network?.networkHandle ?: 0L
        val previous = vpnNetworkHandle.exchange(handle)
        if (previous != handle) {
            setVpnNetworkHandleNative(handle)
            log.d { "VPN network handle $previous to $handle" }
        }
    }

    @JvmStatic
    fun lookupOnUnderlayNetwork(host: String, networkFamily: String): String {
        val network =
            underlayNetwork.load()
                ?: run {
                    log.w { "lookupOnUnderlayNetwork: no underlay network" }
                    log.d { "lookupOnUnderlayNetwork: no underlay for $host" }
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
            log.e(e) { "lookupOnUnderlayNetwork failed" }
            log.d { "lookupOnUnderlayNetwork failed for $host" }
            ""
        }
    }
}
