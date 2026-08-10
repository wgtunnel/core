package com.wgtunnel.backend.util

import com.wgtunnel.backend.model.network.DnsConfig
import com.wgtunnel.backend.model.network.InetNetwork
import inet.ipaddr.IPAddressString

object NetworkUtils {

    fun parseInetNetwork(rawNetwork: String): InetNetwork {
        val network = rawNetwork.trim()
        val slash = network.lastIndexOf('/')
        val rawAddress = if (slash >= 0) network.substring(0, slash).trim() else network
        val rawMask = if (slash >= 0) network.substring(slash + 1).trim() else null

        val addr =
            IPAddressString(rawAddress).address
                ?: throw IllegalArgumentException("Invalid address: $rawAddress")

        val max = if (addr.isIPv4) 32 else 128
        val mask = rawMask?.toIntOrNull() ?: max
        if (mask !in 0..max) {
            throw IllegalArgumentException("Invalid network mask: $rawMask (must be 0-$max)")
        }

        val host = addr.withoutPrefixLength().toCanonicalString()
        return InetNetwork(hostAddress = host, prefixLength = mask)
    }

    fun parseDns(rawServers: String): DnsConfig {
        val servers = mutableListOf<String>()
        val domains = mutableListOf<String>()

        rawServers.split(",").forEach { item ->
            val trimmed = item.trim()
            if (trimmed.isBlank()) return@forEach
            val ip = IPAddressString(trimmed)
            if (ip.isIPAddress) {
                servers += ip.address.withoutPrefixLength().toConvertedString()
            } else {
                domains += trimmed
            }
        }
        return DnsConfig(servers, domains)
    }
}
