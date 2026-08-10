package com.wgtunnel.backend.shell

import co.touchlab.kermit.Logger
import java.util.concurrent.TimeUnit

actual class ShellExecutor {
    private val log = Logger.withTag("ShellExecutor")

    actual fun hasPrivilegedAccess(): Boolean {
        val os = System.getProperty("os.name").lowercase()
        return if (os.contains("win")) {
            // Service/daemon assumed elevated; refine with a real admin check if needed
            true
        } else {
            try {
                val p = ProcessBuilder("id", "-u").redirectErrorStream(true).start()
                val uid = p.inputStream.bufferedReader().readText().trim()
                p.waitFor(2, TimeUnit.SECONDS)
                uid == "0"
            } catch (e: Exception) {
                log.w(e) { "Failed to check uid" }
                false
            }
        }
    }

    actual fun requestPrivilegedAccess(): Boolean = hasPrivilegedAccess()

    actual fun run(command: String): ShellResult {
        val os = System.getProperty("os.name").lowercase()
        val process =
            if (os.contains("win")) {
                    ProcessBuilder("cmd.exe", "/c", command)
                } else {
                    ProcessBuilder("sh", "-c", command)
                }
                .redirectErrorStream(false)
                .start()

        val stdout = process.inputStream.bufferedReader().readLines()
        val stderr = process.errorStream.bufferedReader().readLines()
        val finished = process.waitFor(30, TimeUnit.SECONDS)
        val code =
            if (finished) process.exitValue()
            else {
                process.destroyForcibly()
                -1
            }

        log.d { "Shell exit=$code cmd=$command" }
        return ShellResult(code = code, stdout = stdout, stderr = stderr)
    }
}
