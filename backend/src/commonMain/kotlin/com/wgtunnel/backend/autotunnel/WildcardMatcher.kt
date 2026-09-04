package com.wgtunnel.backend.autotunnel

object WildcardMatcher {
    fun List<String>.matchesWildcardList(value: String): Boolean {
        val excludeValues =
            this.filter { it.startsWith("!") }.map { it.removePrefix("!").toWildcardRegex() }
        val includedValues = this.filter { !it.startsWith("!") }.map { it.toWildcardRegex() }
        val matches = includedValues.filter { it.matches(value) }
        val excludedMatches = excludeValues.filter { it.matches(value) }
        return matches.isNotEmpty() && excludedMatches.isEmpty()
    }

    fun String.toWildcardRegex(): Regex {
        return replaceUnescapedChar("*", ".*").replaceUnescapedChar("?", ".").toRegex()
    }

    private fun String.replaceUnescapedChar(charToReplace: String, replacement: String): String {
        val escapedChar = Regex.escape(charToReplace)
        val regex = "(?<!\\\\)(?<!(?<!\\\\)\\\\)($escapedChar)".toRegex()
        return regex.replace(this) { matchResult ->
            if (
                matchResult.range.first == 0 ||
                    this[matchResult.range.first - 1] != '\\' ||
                    (matchResult.range.first > 1 && this[matchResult.range.first - 2] == '\\')
            ) {
                replacement
            } else {
                matchResult.value
            }
        }
    }
}
