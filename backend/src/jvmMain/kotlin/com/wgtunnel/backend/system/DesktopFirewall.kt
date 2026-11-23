package com.wgtunnel.backend.system

import com.wgtunnel.backend.loadBackendNativeLibrary

internal object DesktopFirewallNative {
    @JvmStatic external fun hasLeftoverRules(): Int

    @JvmStatic external fun release(): Int

    @JvmStatic external fun purge(): Int
}

/**
 * Kill switch rules across daemon restarts. The OS keeps them after the daemon exits and drops them
 * on reboot, so a daemon that exits can leave the machine protected until the next one takes them
 * over.
 */
object DesktopFirewall {
    private val available by lazy { loadBackendNativeLibrary() }

    /** Rules an earlier daemon left enforced, read from the OS. */
    fun hasLeftoverRules(): Boolean = available && DesktopFirewallNative.hasLeftoverRules() == 1

    /**
     * Keeps the current rules enforced after this process exits. Enabling the kill switch in the
     * next process takes them over without a gap.
     */
    fun release(): Boolean = available && DesktopFirewallNative.release() == 0

    /** Removes every kill switch rule, including ones an earlier daemon left. */
    fun purge(): Boolean = available && DesktopFirewallNative.purge() == 0
}
