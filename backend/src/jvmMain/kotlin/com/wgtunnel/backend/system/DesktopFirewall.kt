package com.wgtunnel.backend.system

import com.wgtunnel.backend.loadBackendNativeLibrary
import com.wgtunnel.backend.service.DesktopKillSwitchNative

internal object DesktopFirewallNative {
    @JvmStatic external fun hasLeftoverRules(): Int

    @JvmStatic external fun release(acrossReboot: Int): Int

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
     * Turns the kill switch on with [allowedIps] reachable, without the rest of the backend.
     * Takes over leftover rules without a gap. For the start of the daemon and early boot.
     */
    fun enforce(allowedIps: Collection<String>): Boolean {
        if (!available) return false
        if (DesktopKillSwitchNative.setKillSwitch(1) < 0) return false
        val csv = allowedIps.joinToString(",") { it.trim() }
        return DesktopKillSwitchNative.setKillSwitchAllowedNetworks(csv) >= 0
    }

    /**
     * Keeps the current rules enforced after this process exits. Enabling the kill switch in
     * the next process takes them over without a gap. With [acrossReboot], Windows keeps them
     * through a reboot, enforced before the service starts. Elsewhere the OS drops them on
     * reboot.
     */
    fun release(acrossReboot: Boolean = false): Boolean =
        available && DesktopFirewallNative.release(if (acrossReboot) 1 else 0) == 0

    /** Removes every kill switch rule, including ones an earlier daemon left. */
    fun purge(): Boolean = available && DesktopFirewallNative.purge() == 0
}
