package com.wgtunnel.backend.util

import android.net.TrafficStats

internal actual fun <T> withSocketTag(tag: Int, block: () -> T): T {
    TrafficStats.setThreadStatsTag(tag)
    try {
        return block()
    } finally {
        TrafficStats.clearThreadStatsTag()
    }
}