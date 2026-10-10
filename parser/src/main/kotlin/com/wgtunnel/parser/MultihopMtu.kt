package com.wgtunnel.parser

object MultihopMtu {
    const val DEFAULT_MTU = 1280
    const val WG_OVERHEAD = 80
    const val MAX_ENTRY_MTU = 1500
    const val MIN_EXIT_MTU = 576

    /**
     * Multihop wraps the exit hop's packets inside the entry hop's tunnel, so the entry MTU must be
     * large enough to carry a full exit packet. Grows entry to fit exit (capped to [MAX_ENTRY_MTU])
     */
    fun balance(exit: Config, entry: Config?): Pair<Config, Config?> {
        if (entry == null) return exit to null

        val exitMtu = exit.`interface`.mtu?.takeIf { it > 0 } ?: DEFAULT_MTU
        var entryMtu = exitMtu + WG_OVERHEAD
        var adjustedExitMtu = exitMtu
        if (entryMtu > MAX_ENTRY_MTU) {
            entryMtu = MAX_ENTRY_MTU
            adjustedExitMtu = (entryMtu - WG_OVERHEAD).coerceAtLeast(MIN_EXIT_MTU)
        }

        val balancedExit = exit.copy(`interface` = exit.`interface`.copy(mtu = adjustedExitMtu))
        val balancedEntry = entry.copy(`interface` = entry.`interface`.copy(mtu = entryMtu))
        return balancedExit to balancedEntry
    }
}
