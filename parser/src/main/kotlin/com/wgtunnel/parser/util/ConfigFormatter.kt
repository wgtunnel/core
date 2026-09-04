package com.wgtunnel.parser.util

import com.wgtunnel.parser.ActivePeer
import com.wgtunnel.parser.ConfigQuickInclude
import com.wgtunnel.parser.InterfaceSection
import com.wgtunnel.parser.PeerSection
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant
import nl.jacobras.humanreadable.HumanReadable

object ConfigFormatter {

    fun appendInterfaceSection(
        sb: StringBuilder,
        iface: InterfaceSection,
        hidePrivateKey: Boolean = false,
        include: ConfigQuickInclude = ConfigQuickInclude.All,
    ) {
        if (include.core) {
            iface.comments.forEach { sb.appendLine(it) }
        }
        sb.appendLine("[Interface]")
        if (include.core) {
            sb.appendLine("PrivateKey = ${if (hidePrivateKey) "(hidden)" else iface.privateKey}")
            iface.address?.let { sb.appendLine("Address = $it") }
        }
        if (include.dns) {
            appendOptional(sb, "DNS", iface.dns, include.placeholders)
        }

        if (include.core) {
            iface.preUp?.forEach { sb.appendLine("PreUp = $it") }
            iface.postUp?.forEach { sb.appendLine("PostUp = $it") }
            iface.preDown?.forEach { sb.appendLine("PreDown = $it") }
            iface.postDown?.forEach { sb.appendLine("PostDown = $it") }

            iface.listenPort?.let { sb.appendLine("ListenPort = $it") }
            iface.mtu?.let { sb.appendLine("MTU = $it") }
            iface.fwMark?.let { sb.appendLine("FwMark = $it") }
            iface.table?.let { sb.appendLine("Table = $it") }
            iface.saveConfig?.let { sb.appendLine("SaveConfig = $it") }
        }

        if (include.amnezia) {
            val placeholders = include.placeholders
            appendOptional(sb, "Jc", iface.jC, placeholders)
            appendOptional(sb, "Jmin", iface.jMin, placeholders)
            appendOptional(sb, "Jmax", iface.jMax, placeholders)
            appendOptional(sb, "S1", iface.s1, placeholders)
            appendOptional(sb, "S2", iface.s2, placeholders)
            appendOptional(sb, "S3", iface.s3, placeholders)
            appendOptional(sb, "S4", iface.s4, placeholders)
            appendOptional(sb, "H1", iface.h1, placeholders)
            appendOptional(sb, "H2", iface.h2, placeholders)
            appendOptional(sb, "H3", iface.h3, placeholders)
            appendOptional(sb, "H4", iface.h4, placeholders)
            appendOptional(sb, "I1", iface.i1, placeholders)
            appendOptional(sb, "I2", iface.i2, placeholders)
            appendOptional(sb, "I3", iface.i3, placeholders)
            appendOptional(sb, "I4", iface.i4, placeholders)
            appendOptional(sb, "I5", iface.i5, placeholders)
            appendOptional(sb, "HeaderProtectionKey", iface.headerProtectionKey, placeholders)
            appendOptional(sb, "ContentPaddingAddition", iface.contentPaddingAddition, placeholders)
            appendOptional(sb, "RekeyAfterTime", iface.rekeyAfterTime, placeholders)
            appendOptional(sb, "RekeyTimeout", iface.rekeyTimeout, placeholders)
            appendOptional(sb, "RejectAfterTime", iface.rejectAfterTime, placeholders)
            appendOptional(sb, "KeepaliveTimeout", iface.keepaliveTimeout, placeholders)
            appendOptional(sb, "MaxHandshakeAttempts", iface.maxHandshakeAttempts, placeholders)
            appendOptional(sb, "RandomTrailers", iface.randomTrailers, placeholders)
            appendOptional(sb, "DisableCookies", iface.disableCookies, placeholders)
        }

        if (include.core) {
            iface.includedApplications
                ?.takeIf { it.isNotEmpty() }
                ?.let { sb.appendLine("IncludedApplications = ${it.joinToString(",")}") }
            iface.excludedApplications
                ?.takeIf { it.isNotEmpty() }
                ?.let { sb.appendLine("ExcludedApplications = ${it.joinToString(",")}") }
        }
    }

    private fun appendOptional(
        sb: StringBuilder,
        key: String,
        value: Any?,
        placeholders: Boolean,
    ) {
        if (value != null) {
            sb.appendLine("$key = $value")
        } else if (placeholders) {
            sb.appendLine("$key = ")
        }
    }

    fun appendPeerSection(sb: StringBuilder, peer: PeerSection) {
        peer.comments.forEach { sb.appendLine(it) }
        sb.append("\n[Peer]\n")
        appendCommonPeerFields(
            sb,
            peer.publicKey,
            peer.endpoint,
            peer.allowedIPs,
            peer.presharedKey,
            peer.persistentKeepalive,
        )
    }

    fun appendActivePeerSection(sb: StringBuilder, peer: ActivePeer) {
        sb.append("\n[Peer]\n")
        appendCommonPeerFields(
            sb,
            peer.publicKey,
            peer.endpoint,
            peer.allowedIPs,
            peer.presharedKey,
            peer.persistentKeepalive,
        )
        appendRuntimeStats(sb, peer)
    }

    private fun appendCommonPeerFields(
        sb: StringBuilder,
        publicKey: String,
        endpoint: String?,
        allowedIPs: String?,
        presharedKey: String?,
        persistentKeepalive: String?,
    ) {
        sb.appendLine("PublicKey = $publicKey")
        endpoint?.let { sb.appendLine("Endpoint = $it") }
        allowedIPs?.let { sb.appendLine("AllowedIPs = $it") }
        if (
            presharedKey != null && presharedKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ) {
            sb.appendLine("PresharedKey = $presharedKey")
        }
        persistentKeepalive
            ?.takeIf { it.isNotBlank() && it != "0" }
            ?.let { sb.appendLine("PersistentKeepalive = $it") }
    }

    private fun appendRuntimeStats(sb: StringBuilder, peer: ActivePeer) {
        peer.lastHandshakeSeconds?.let { seconds ->
            if (seconds == 0L) {
                sb.appendLine("LastHandshake =")
            } else {
                val handshakeInstant = Instant.fromEpochSeconds(seconds)
                val agoDuration = Clock.System.now() - handshakeInstant
                sb.appendLine("LastHandshake = ${agoDuration.toDetailedString()} ago")
            }
        }
        peer.txBytes?.let { sb.appendLine("TxBytes = ${HumanReadable.fileSize(it, decimals = 1)}") }
        peer.rxBytes?.let { sb.appendLine("RxBytes = ${HumanReadable.fileSize(it, decimals = 1)}") }
    }

    private fun Duration.toDetailedString(): String {
        val days = inWholeDays
        val hours = toComponents { _, h, _, _, _ -> h }
        val minutes = toComponents { _, _, m, _, _ -> m }
        val seconds = toComponents { _, _, _, s, _ -> s }

        val parts = mutableListOf<String>()
        if (days > 0) parts.add("$days day${if (days > 1) "s" else ""}")
        if (hours > 0) parts.add("$hours hour${if (hours > 1) "s" else ""}")
        if (minutes > 0) parts.add("$minutes minute${if (minutes > 1) "s" else ""}")
        if (seconds > 0) parts.add("$seconds second${if (seconds > 1) "s" else ""}")

        return if (parts.isEmpty()) "0 seconds" else parts.joinToString(" ")
    }
}
