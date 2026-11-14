package com.wgtunnel.parser.archive

import java.io.InputStream
import java.io.OutputStream
import java.text.Normalizer
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Reads and writes the zip of `.conf` files that WG Tunnel exports.
 *
 * File names inside the zip are plain ASCII, because some extractors ignore the zip flags.
 */
object ConfigArchive {

    data class Entry(val name: String, val quickConfig: String)

    const val CONF_EXTENSION = ".conf"

    private const val NAME_PREFIX = "# Name = "
    private const val FALLBACK_NAME = "tunnel"
    private const val MAX_NAME_LENGTH = 64
    private const val MAX_ENTRY_BYTES = 1024 * 1024

    private val DISALLOWED = Regex("[^A-Za-z0-9 ._()+,-]")
    private val UNDERSCORES = Regex("_{2,}")
    private val SPACES = Regex(" {2,}")
    private val MARKS = Regex("\\p{M}+")
    private val WINDOWS_RESERVED = Regex("(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?$")

    fun write(out: OutputStream, entries: List<Entry>) {
        val used = mutableSetOf<String>()
        val zip = ZipOutputStream(out)
        entries.forEach { entry ->
            val fileName = uniqueName(entryName(entry.name), used) + CONF_EXTENSION
            zip.putNextEntry(ZipEntry(fileName))
            zip.write(withNameComment(entry.quickConfig, entry.name).encodeToByteArray())
            zip.closeEntry()
        }
        zip.finish()
    }

    /**
     * Reads the `.conf` files in a zip, ignoring folders, hidden files and blank configs.
     */
    fun read(input: InputStream): List<Entry> {
        val entries = mutableListOf<Entry>()
        ZipInputStream(input).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                val baseName = entry.name.substringAfterLast('/').substringAfterLast('\\')
                if (
                    !entry.isDirectory &&
                        !baseName.startsWith(".") &&
                        baseName.endsWith(CONF_EXTENSION, ignoreCase = true)
                ) {
                    val content = readLimited(zip)?.decodeToString()
                    if (!content.isNullOrBlank()) {
                        entries.add(Entry(baseName.dropLast(CONF_EXTENSION.length), content))
                    }
                }
                zip.closeEntry()
            }
        }
        return entries
    }

    /**
     * Puts a name comment on the first line of the quick config and replacing existing if present.
     */
    fun withNameComment(quickConfig: String, name: String): String {
        val cleanName = name.replace(Regex("[\\r\\n]+"), " ").trim()
        val lines = quickConfig.removePrefix("﻿").lines().toMutableList()
        // The parser takes the name from the first comment before any section
        val firstComment =
            lines
                .asSequence()
                .map { it.trim() }
                .takeWhile { !it.startsWith("[") }
                .indexOfFirst { it.startsWith("#") || it.startsWith(";") }
        if (firstComment >= 0) {
            val content = lines[firstComment].trim().trimStart('#', ' ', '\t').trim()
            if (content.startsWith("Name", ignoreCase = true)) lines.removeAt(firstComment)
        }
        val body = lines.joinToString("\n").trimStart('\n')
        if (cleanName.isEmpty()) return body
        return "$NAME_PREFIX$cleanName\n$body"
    }

    /** An ASCII file name for [name], without the extension. */
    internal fun entryName(name: String): String {
        val latin = buildString { name.forEach { append(transliterate(it)) } }
        val ascii =
            Normalizer.normalize(latin, Normalizer.Form.NFKD)
                .replace(MARKS, "")
                .replace(DISALLOWED, "_")
                .replace(UNDERSCORES, "_")
                .replace(SPACES, " ")
                .take(MAX_NAME_LENGTH)
                .trim(' ', '.', '_')
        return when {
            ascii.isEmpty() -> FALLBACK_NAME
            WINDOWS_RESERVED.matches(ascii) -> "_$ascii"
            else -> ascii
        }
    }

    // Case-insensitive, as on Windows and macOS file systems
    private fun uniqueName(base: String, used: MutableSet<String>): String {
        var candidate = base
        var index = 2
        while (!used.add(candidate.lowercase())) {
            candidate = "$base ($index)"
            index++
        }
        return candidate
    }

    private fun readLimited(zip: ZipInputStream): ByteArray? {
        val bytes = zip.readNBytes(MAX_ENTRY_BYTES + 1)
        return bytes.takeIf { it.size <= MAX_ENTRY_BYTES }
    }

    private fun transliterate(char: Char): String {
        val latin = CYRILLIC[char.lowercaseChar()] ?: return char.toString()
        return if (char.isUpperCase()) latin.replaceFirstChar { it.uppercaseChar() } else latin
    }

    private val CYRILLIC =
        mapOf(
            'а' to "a",
            'б' to "b",
            'в' to "v",
            'г' to "g",
            'д' to "d",
            'е' to "e",
            'ё' to "e",
            'ж' to "zh",
            'з' to "z",
            'и' to "i",
            'й' to "y",
            'к' to "k",
            'л' to "l",
            'м' to "m",
            'н' to "n",
            'о' to "o",
            'п' to "p",
            'р' to "r",
            'с' to "s",
            'т' to "t",
            'у' to "u",
            'ф' to "f",
            'х' to "kh",
            'ц' to "ts",
            'ч' to "ch",
            'ш' to "sh",
            'щ' to "shch",
            'ъ' to "",
            'ы' to "y",
            'ь' to "",
            'э' to "e",
            'ю' to "yu",
            'я' to "ya",
            'і' to "i",
            'ї' to "yi",
            'є' to "ye",
            'ґ' to "g",
            'ў' to "u",
        )
}
