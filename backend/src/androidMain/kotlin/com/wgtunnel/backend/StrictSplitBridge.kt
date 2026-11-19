package com.wgtunnel.backend

import android.content.Context
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.os.Build
import android.os.Process
import android.system.OsConstants
import androidx.annotation.RequiresApi
import java.net.InetSocketAddress

/**
 * Policy for the userspace packet filter. The snapshot is published before the native filter is
 * installed, and cleared only after the native filter is removed.
 *
 * Unresolved owners are dropped. That includes kernel ICMP, a UID of 0, and any lookup that throws.
 */
internal object StrictSplitBridge {
    const val OFF = 0
    const val INCLUDE = 1
    const val EXCLUDE = 2

    private data class Policy(val mode: Int, val packages: Set<String>)

    @Volatile private var policy = Policy(OFF, emptySet())

    @Volatile private var appContext: Context? = null

    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    fun install(mode: Int, packages: Set<String>) {
        policy = Policy(mode, packages)
        applyStrictSplitFilter(1)
    }

    fun clear() {
        applyStrictSplitFilter(0)
        policy = Policy(OFF, emptySet())
    }

    @JvmStatic private external fun applyStrictSplitFilter(active: Int)

    @JvmStatic
    fun allow(
        network: String,
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
    ): Boolean {
        val current = policy
        if (current.mode == OFF || current.packages.isEmpty()) return true
        val context = appContext ?: return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
        return try {
            val uid = ownerUid(context, network, srcIp, srcPort, dstIp, dstPort)
            if (uid == Process.INVALID_UID || uid == 0) return false
            val pkgs = context.packageManager.getPackagesForUid(uid)?.toSet().orEmpty()
            if (pkgs.isEmpty()) return false
            val hit = pkgs.any { it in current.packages }
            when (current.mode) {
                INCLUDE -> hit
                EXCLUDE -> !hit
                else -> false
            }
        } catch (_: Throwable) {
            false
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun ownerUid(
        context: Context,
        network: String,
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
    ): Int {
        val protocol =
            when (network) {
                "tcp" -> OsConstants.IPPROTO_TCP
                "udp" -> OsConstants.IPPROTO_UDP
                else -> return Process.INVALID_UID
            }
        val cm =
            context.getSystemService(ConnectivityManager::class.java) ?: return Process.INVALID_UID
        val local = InetSocketAddress(InetAddresses.parseNumericAddress(srcIp), srcPort)
        val remote = InetSocketAddress(InetAddresses.parseNumericAddress(dstIp), dstPort)
        return cm.getConnectionOwnerUid(protocol, local, remote)
    }
}
