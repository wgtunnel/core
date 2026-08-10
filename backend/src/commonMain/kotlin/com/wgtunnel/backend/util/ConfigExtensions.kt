package com.wgtunnel.backend.util

import com.wgtunnel.backend.model.dns.ResolvedHost
import com.wgtunnel.parser.Config
import com.wgtunnel.parser.PeerSection

fun Config.hasDynamicEndpoints(): Boolean {
    return peers.any { !it.isStaticallyConfigured && it.endpoint != null }
}

internal fun Config.buildResolvedPeers(hostMap: Map<PublicKey, ResolvedHost>): List<PeerSection> {
    return this.peers.map { peer ->
        val resolved = hostMap[peer.publicKey] ?: return@map peer

        val port =
            resolved.forcedPort?.toString()
                ?: peer.endpoint?.substringAfterLast(":")
                ?: return@map peer

        peer.copy(endpoint = "${resolved.host}:$port")
    }
}

fun Config.parseDnsServersOnly(): List<String> =
    `interface`.dns?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
