package com.wgtunnel.backend

import android.os.Build

internal actual fun applyStrictSplit(
    enabled: Boolean,
    included: List<String>,
    excluded: List<String>,
) {
    if (!enabled || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
        StrictSplitBridge.clear()
        return
    }
    val mode: Int
    val packages: Set<String>
    when {
        included.isNotEmpty() -> {
            mode = StrictSplitBridge.INCLUDE
            packages = included.toSet()
        }
        excluded.isNotEmpty() -> {
            mode = StrictSplitBridge.EXCLUDE
            packages = excluded.toSet()
        }
        else -> {
            StrictSplitBridge.clear()
            return
        }
    }
    StrictSplitBridge.install(mode, packages)
}
