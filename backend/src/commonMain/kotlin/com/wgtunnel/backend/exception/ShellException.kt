package com.wgtunnel.backend.exception

sealed class ShellException(
    override val message: String,
    override val cause: Throwable? = null,
) : Exception(message, cause) {

    class NoAccess :
        ShellException("Root access is not granted. Please grant root permissions.")

    class CommandFailed(val command: String, val exitCode: Int, val stderr: String? = null) :
        ShellException(
            buildString {
                append("Root command failed")
                append(" (exit code: $exitCode)")
                append(": $command")

                if (!stderr.isNullOrBlank()) {
                    append("\n$stderr")
                }
            }
        )

    class CommandTimedOut(val command: String, val timeoutMs: Long) :
        ShellException("Root command timed out after ${timeoutMs}ms: $command")

    class ShellDied(cause: Throwable? = null) :
        ShellException("Root shell terminated unexpectedly", cause)
}