// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/gold/HermesBundlePatcher.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget 1.247.1 Hermes HBC v96

package io.github.ryuuseiakira.locket.patches.locket.gold

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Pure-Kotlin Hermes bytecode (HBC v96) parser and in-place patcher for Locket's
 * `androidGoldSubscriptionOverride` feature-flag helper.
 *
 * Attachment: `assets/index.android.bundle` inside `com.locket.Locket`.
 * Mechanism: Validates HBC v96 header and trailing SHA-1 integrity, resolves target string IDs
 * from the string table, locates the unique `androidGoldSubscriptionOverride` function and its
 * `GetById("getBoolean"); LoadConstString[LongIndex]("android_gold_subscription_override"); Call2; Ret`
 * sequence, overwrites `Call2` (5 bytes) with `LoadConstTrue <rDst>; Ret <rDst>; Unreachable`,
 * and recomputes the trailing 20-byte SHA-1 footer.
 * Constraint: Fixed-length 5-byte rewrite preserves all function and table offsets; requires exact
 * HBC v96 format, intact SHA-1 footer, and a single unambiguous match site.
 */
object HermesBundlePatcher {
    const val HBC_MAGIC: Long = 0x1f1903c103bc1fc6L
    const val HBC_VERSION: Int = 96
    const val HEADER_SIZE: Int = 128
    const val SHA1_SIZE: Int = 20

    private const val SMALL_FUNC_HEADER_SIZE: Int = 16
    private const val LARGE_FUNC_HEADER_SIZE: Int = 32
    private const val OVERFLOW_STRING_ENTRY_SIZE: Int = 8

    private const val OFF_MAGIC: Int = 0x00
    private const val OFF_VERSION: Int = 0x08
    private const val OFF_FILE_LENGTH: Int = 0x20
    private const val OFF_FUNCTION_COUNT: Int = 0x28
    private const val OFF_STRING_KIND_COUNT: Int = 0x2c
    private const val OFF_IDENTIFIER_COUNT: Int = 0x30
    private const val OFF_STRING_COUNT: Int = 0x34
    private const val OFF_OVERFLOW_STRING_COUNT: Int = 0x38
    private const val OFF_STRING_STORAGE_SIZE: Int = 0x3c

    private const val OP_UNREACHABLE: Byte = 0x00
    private const val OP_GET_BY_ID: Byte = 0x37
    private const val OP_CALL2: Byte = 0x53
    private const val OP_RET: Byte = 0x5c
    private const val OP_LOAD_CONST_STRING: Byte = 0x73
    private const val OP_LOAD_CONST_STRING_LONG_INDEX: Byte = 0x74
    private const val OP_LOAD_CONST_TRUE: Byte = 0x78

    private const val FN_GOLD_OVERRIDE = "androidGoldSubscriptionOverride"
    private const val FN_GET_BOOLEAN = "getBoolean"
    private const val KEY_GOLD_OVERRIDE = "android_gold_subscription_override"

    private const val MIN_SEQUENCE_LEN = 17

    data class PatchResult(
        val bytes: ByteArray,
        val functionIndex: Int,
        val patchOffset: Int,
        val returnRegister: Int,
    )

    private data class StringIds(
        val funcNameId: Int,
        val getBooleanId: Int,
        val flagKeyId: Int,
    )

    private data class MatchSite(
        val functionIndex: Int,
        val callOffset: Int,
        val returnRegister: Int,
    )

    fun patch(bundle: ByteArray): PatchResult {
        require(bundle.size >= HEADER_SIZE + SHA1_SIZE) {
            "Hermes bundle is too small (${bundle.size} bytes)."
        }

        val magic = u64Le(bundle, OFF_MAGIC)
        require(magic == HBC_MAGIC) {
            "Unexpected Hermes magic: 0x${java.lang.Long.toHexString(magic)}."
        }

        val version = u32Le(bundle, OFF_VERSION)
        require(version == HBC_VERSION.toLong()) {
            "Unsupported Hermes bytecode version $version (expected $HBC_VERSION)."
        }

        val fileLength = u32Le(bundle, OFF_FILE_LENGTH)
        require(fileLength == bundle.size.toLong()) {
            "Hermes header fileLength ($fileLength) does not match bundle size (${bundle.size})."
        }

        val contentEnd = bundle.size - SHA1_SIZE
        val actualDigest = bundle.copyOfRange(contentEnd, bundle.size)
        val expectedDigest = sha1(bundle, contentEnd)
        require(MessageDigest.isEqual(expectedDigest, actualDigest)) {
            "Hermes bundle trailing SHA-1 integrity check failed."
        }

        val functionCount = readCount(bundle, OFF_FUNCTION_COUNT, contentEnd, "functionCount")
        val stringKindCount = readCount(bundle, OFF_STRING_KIND_COUNT, contentEnd, "stringKindCount")
        val identifierCount = readCount(bundle, OFF_IDENTIFIER_COUNT, contentEnd, "identifierCount")
        val stringCount = readCount(bundle, OFF_STRING_COUNT, contentEnd, "stringCount")
        val overflowStringCount = readCount(bundle, OFF_OVERFLOW_STRING_COUNT, contentEnd, "overflowStringCount")
        val stringStorageSize = readCount(bundle, OFF_STRING_STORAGE_SIZE, contentEnd, "stringStorageSize")

        val funcTableEnd = HEADER_SIZE.toLong() + functionCount.toLong() * SMALL_FUNC_HEADER_SIZE
        val kindTableOff = align4(funcTableEnd)
        val identTableOff = align4(kindTableOff + stringKindCount.toLong() * 4L)
        val smallStrOff = align4(identTableOff + identifierCount.toLong() * 4L)
        val ovfStrOff = align4(smallStrOff + stringCount.toLong() * 4L)
        val strStorageOff = align4(ovfStrOff + overflowStringCount.toLong() * OVERFLOW_STRING_ENTRY_SIZE)
        val strStorageEnd = strStorageOff + stringStorageSize.toLong()

        require(strStorageEnd <= contentEnd.toLong()) {
            "Hermes metadata tables extend past content end ($strStorageEnd > $contentEnd)."
        }

        val ids = resolveTargetStringIds(
            bundle = bundle,
            smallStrOff = smallStrOff.toInt(),
            ovfStrOff = ovfStrOff.toInt(),
            strStorageOff = strStorageOff.toInt(),
            stringCount = stringCount,
            overflowStringCount = overflowStringCount,
            stringStorageSize = stringStorageSize,
        )

        val match = findUniqueMatch(
            bundle = bundle,
            functionCount = functionCount,
            contentEnd = contentEnd,
            ids = ids,
        )

        val patched = bundle.copyOf()
        val callOff = match.callOffset
        val rDstByte = match.returnRegister.toByte()
        patched[callOff] = OP_LOAD_CONST_TRUE
        patched[callOff + 1] = rDstByte
        patched[callOff + 2] = OP_RET
        patched[callOff + 3] = rDstByte
        patched[callOff + 4] = OP_UNREACHABLE

        val newDigest = sha1(patched, contentEnd)
        System.arraycopy(newDigest, 0, patched, contentEnd, SHA1_SIZE)

        return PatchResult(
            bytes = patched,
            functionIndex = match.functionIndex,
            patchOffset = callOff,
            returnRegister = match.returnRegister,
        )
    }

    private fun resolveTargetStringIds(
        bundle: ByteArray,
        smallStrOff: Int,
        ovfStrOff: Int,
        strStorageOff: Int,
        stringCount: Int,
        overflowStringCount: Int,
        stringStorageSize: Int,
    ): StringIds {
        val fnNameAscii = FN_GOLD_OVERRIDE.toByteArray(StandardCharsets.US_ASCII)
        val getBoolAscii = FN_GET_BOOLEAN.toByteArray(StandardCharsets.US_ASCII)
        val flagKeyAscii = KEY_GOLD_OVERRIDE.toByteArray(StandardCharsets.US_ASCII)

        var funcNameId = -1
        var getBooleanId = -1
        var flagKeyId = -1

        for (i in 0 until stringCount) {
            val entry = i32Le(bundle, smallStrOff + i * 4)
            val isUtf16 = (entry and 1) != 0
            val smallOffset = (entry ushr 1) and 0x7fffff
            val smallLen = (entry ushr 24) and 0xff

            val realOffset: Long
            val charLen: Long
            if (smallLen == 0xff) {
                require(smallOffset < overflowStringCount) {
                    "Overflow string index $smallOffset out of bounds ($overflowStringCount)."
                }
                val ovfPos = ovfStrOff + smallOffset * OVERFLOW_STRING_ENTRY_SIZE
                realOffset = u32Le(bundle, ovfPos)
                charLen = u32Le(bundle, ovfPos + 4)
            } else {
                realOffset = smallOffset.toLong()
                charLen = smallLen.toLong()
            }

            val byteLen = if (isUtf16) charLen * 2L else charLen
            require(realOffset + byteLen <= stringStorageSize.toLong()) {
                "String #$i range ($realOffset + $byteLen) exceeds stringStorageSize ($stringStorageSize)."
            }

            val startPos = strStorageOff + realOffset.toInt()
            when {
                matchesAscii(bundle, startPos, charLen, isUtf16, fnNameAscii) -> {
                    require(funcNameId == -1) { "Duplicate string entry for '$FN_GOLD_OVERRIDE'." }
                    funcNameId = i
                }
                matchesAscii(bundle, startPos, charLen, isUtf16, getBoolAscii) -> {
                    require(getBooleanId == -1) { "Duplicate string entry for '$FN_GET_BOOLEAN'." }
                    getBooleanId = i
                }
                matchesAscii(bundle, startPos, charLen, isUtf16, flagKeyAscii) -> {
                    require(flagKeyId == -1) { "Duplicate string entry for '$KEY_GOLD_OVERRIDE'." }
                    flagKeyId = i
                }
            }
        }

        require(funcNameId != -1) { "Missing required string '$FN_GOLD_OVERRIDE'." }
        require(getBooleanId != -1) { "Missing required string '$FN_GET_BOOLEAN'." }
        require(flagKeyId != -1) { "Missing required string '$KEY_GOLD_OVERRIDE'." }

        return StringIds(funcNameId = funcNameId, getBooleanId = getBooleanId, flagKeyId = flagKeyId)
    }

    private fun findUniqueMatch(
        bundle: ByteArray,
        functionCount: Int,
        contentEnd: Int,
        ids: StringIds,
    ): MatchSite {
        var namedFunctionCount = 0
        val matches = mutableListOf<MatchSite>()

        for (funcIdx in 0 until functionCount) {
            val hOff = HEADER_SIZE + funcIdx * SMALL_FUNC_HEADER_SIZE
            val w0 = i32Le(bundle, hOff)
            val w1 = i32Le(bundle, hOff + 4)
            val w2 = i32Le(bundle, hOff + 8)
            val w3 = i32Le(bundle, hOff + 12)
            val flags = (w3 ushr 24) and 0xff
            val overflowed = ((flags ushr 5) and 1) != 0

            val codeOffset: Long
            val codeSize: Int
            val nameIdx: Int
            if (!overflowed) {
                codeOffset = (w0 and 0x1ffffff).toLong()
                codeSize = w1 and 0x7fff
                nameIdx = (w1 ushr 15) and 0x1ffff
            } else {
                val largeOffset = (((w2 and 0xffff).toLong() shl 16) or (w0 and 0xffff).toLong())
                require(largeOffset >= HEADER_SIZE && largeOffset + LARGE_FUNC_HEADER_SIZE <= contentEnd) {
                    "LargeFuncHeader offset $largeOffset for function #$funcIdx out of bounds."
                }
                val lo = largeOffset.toInt()
                codeOffset = u32Le(bundle, lo)
                val largeSize = u32Le(bundle, lo + 8)
                val largeName = u32Le(bundle, lo + 12)
                require(largeSize <= Int.MAX_VALUE && largeName <= Int.MAX_VALUE) {
                    "LargeFuncHeader fields out of range for function #$funcIdx."
                }
                codeSize = largeSize.toInt()
                nameIdx = largeName.toInt()
            }

            if (nameIdx != ids.funcNameId) continue

            namedFunctionCount++
            require(codeOffset >= HEADER_SIZE && codeOffset + codeSize <= contentEnd) {
                "Bytecode range ($codeOffset + $codeSize) for '$FN_GOLD_OVERRIDE' (#$funcIdx) out of bounds."
            }

            collectMatchesInFunction(
                bundle = bundle,
                functionIndex = funcIdx,
                codeStart = codeOffset.toInt(),
                codeSize = codeSize,
                getBooleanId = ids.getBooleanId,
                flagKeyId = ids.flagKeyId,
                out = matches,
            )
        }

        require(namedFunctionCount == 1) {
            "Expected 1 '$FN_GOLD_OVERRIDE' function, found $namedFunctionCount."
        }
        require(matches.size == 1) {
            "Expected 1 patchable Call2 site in '$FN_GOLD_OVERRIDE', found ${matches.size}."
        }
        return matches[0]
    }

    private fun collectMatchesInFunction(
        bundle: ByteArray,
        functionIndex: Int,
        codeStart: Int,
        codeSize: Int,
        getBooleanId: Int,
        flagKeyId: Int,
        out: MutableList<MatchSite>,
    ) {
        if (codeSize < MIN_SEQUENCE_LEN) return

        val codeEnd = codeStart + codeSize
        val lastStart = codeEnd - MIN_SEQUENCE_LEN
        var offset = codeStart

        while (offset <= lastStart) {
            if (bundle[offset] != OP_GET_BY_ID || u16Le(bundle, offset + 4) != getBooleanId) {
                offset++
                continue
            }

            val rFn = bundle[offset + 1]
            val rObj = bundle[offset + 2]
            val next = offset + 6

            val rArg: Byte
            val callOffset: Int
            when (bundle[next]) {
                OP_LOAD_CONST_STRING -> {
                    if (u16Le(bundle, next + 2) != flagKeyId) {
                        offset++
                        continue
                    }
                    rArg = bundle[next + 1]
                    callOffset = next + 4
                }
                OP_LOAD_CONST_STRING_LONG_INDEX -> {
                    if (next + 6 + 7 > codeEnd || u32Le(bundle, next + 2) != flagKeyId.toLong()) {
                        offset++
                        continue
                    }
                    rArg = bundle[next + 1]
                    callOffset = next + 6
                }
                else -> {
                    offset++
                    continue
                }
            }

            if (callOffset + 7 <= codeEnd &&
                bundle[callOffset] == OP_CALL2 &&
                bundle[callOffset + 2] == rFn &&
                bundle[callOffset + 3] == rObj &&
                bundle[callOffset + 4] == rArg
            ) {
                val rDst = bundle[callOffset + 1]
                if (bundle[callOffset + 5] == OP_RET && bundle[callOffset + 6] == rDst) {
                    out.add(
                        MatchSite(
                            functionIndex = functionIndex,
                            callOffset = callOffset,
                            returnRegister = rDst.toInt() and 0xff,
                        )
                    )
                    offset = callOffset + 7
                    continue
                }
            }

            offset++
        }
    }

    private fun matchesAscii(
        bundle: ByteArray,
        startPos: Int,
        charLen: Long,
        isUtf16: Boolean,
        ascii: ByteArray,
    ): Boolean {
        if (charLen != ascii.size.toLong()) return false
        return if (!isUtf16) {
            for (k in ascii.indices) {
                if (bundle[startPos + k] != ascii[k]) return false
            }
            true
        } else {
            for (k in ascii.indices) {
                if (bundle[startPos + k * 2] != ascii[k] || bundle[startPos + k * 2 + 1] != 0.toByte()) {
                    return false
                }
            }
            true
        }
    }

    private fun readCount(bundle: ByteArray, offset: Int, maxBound: Int, name: String): Int {
        val value = u32Le(bundle, offset)
        require(value <= Int.MAX_VALUE.toLong() && value <= maxBound.toLong()) {
            "Hermes header $name ($value) exceeds content bound ($maxBound)."
        }
        return value.toInt()
    }

    private fun align4(value: Long): Long = (value + 3L) and -4L

    private fun u16Le(bytes: ByteArray, offset: Int): Int {
        return (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun i32Le(bytes: ByteArray, offset: Int): Int {
        return (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)
    }

    private fun u32Le(bytes: ByteArray, offset: Int): Long = i32Le(bytes, offset).toLong() and 0xffffffffL

    private fun u64Le(bytes: ByteArray, offset: Int): Long {
        var result = 0L
        for (i in 0 until 8) {
            result = result or ((bytes[offset + i].toLong() and 0xffL) shl (i * 8))
        }
        return result
    }

    private fun sha1(bytes: ByteArray, length: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-1")
        digest.update(bytes, 0, length)
        return digest.digest()
    }
}
