package com.wgtunnel.backend.system

import com.wgtunnel.backend.loadBackendNativeLibrary

internal object ElevationNative {
    @JvmStatic external fun runAsAdmin(path: String, args: String): Int
}

/** Runs a program through the UAC prompt. Windows only. */
object Elevation {
    private val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")
    private val available by lazy { isWindows && loadBackendNativeLibrary() }

    sealed interface Result {
        data class Exited(val code: Int) : Result

        data object Cancelled : Result

        data object Failed : Result
    }

    /** Blocks until the program exits, up to two minutes. */
    fun runAsAdmin(path: String, args: String): Result {
        if (!available) return Result.Failed
        return when (
            val code = runCatching { ElevationNative.runAsAdmin(path, args) }.getOrDefault(-1)
        ) {
            -2 -> Result.Cancelled
            -1 -> Result.Failed
            else -> Result.Exited(code)
        }
    }
}
