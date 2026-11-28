// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Shared Hermes HBC v96 parser and patcher

package io.github.ryuuseiakira.locket.patches.shared

import java.security.MessageDigest

/**
 * Shared pure-Kotlin Hermes bytecode (HBC v96) parser, verifier, and fixed-length patcher for
 * `assets/index.android.bundle`.
 *
 * Attachment: Hermes HBC v96 buffer (`assets/index.android.bundle`) parsed by header, function
 * table, string table, and trailing SHA-1 integrity footer.
 * Mechanism: Validates magic, version 96, exact `fileLength`, and trailing SHA-1 digest, maps
 * needed string table indices and function headers (`SmallFuncHeader` and `LargeFuncHeader`),
 * applies instruction-aligned length-preserving in-place bytecode rewrites, and recomputes the
 * trailing SHA-1 footer.
 * Constraint: Fixed-length in-place writes preserve all function/table offsets; every rewrite rule
 * must resolve a single unambiguous site and pass bounds and prologue/sequence verification.
 */
object HermesHbc96 {
    const val BUNDLE_PATH: String = "assets/index.android.bundle"

    const val HBC_MAGIC: Long = 0x1f1903c103bc1fc6L
    const val HBC_VERSION: Int = 96
    const val HEADER_SIZE: Int = 128
    const val SHA1_SIZE: Int = 20

    const val OP_UNREACHABLE: Byte = 0x00
    const val OP_NEW_OBJECT: Byte = 0x03
    const val OP_GET_BY_ID_SHORT: Byte = 0x36
    const val OP_GET_BY_ID: Byte = 0x37
    const val OP_GET_BY_ID_LONG: Byte = 0x38
    const val OP_TRY_GET_BY_ID: Byte = 0x39
    const val OP_TRY_GET_BY_ID_LONG: Byte = 0x3a
    const val OP_PUT_BY_ID: Byte = 0x3b
    const val OP_PUT_BY_ID_LONG: Byte = 0x3c
    const val OP_TRY_PUT_BY_ID: Byte = 0x3d
    const val OP_TRY_PUT_BY_ID_LONG: Byte = 0x3e
    const val OP_PUT_NEW_OWN_BY_ID_SHORT: Byte = 0x3f
    const val OP_PUT_NEW_OWN_BY_ID: Byte = 0x40
    const val OP_PUT_NEW_OWN_BY_ID_LONG: Byte = 0x41
    const val OP_PUT_NEW_OWN_NE_BY_ID: Byte = 0x42
    const val OP_PUT_NEW_OWN_NE_BY_ID_LONG: Byte = 0x43
    const val OP_CALL2: Byte = 0x53
    const val OP_RET: Byte = 0x5c
    const val OP_LOAD_CONST_STRING: Byte = 0x73
    const val OP_LOAD_CONST_STRING_LONG_INDEX: Byte = 0x74
    const val OP_LOAD_CONST_UNDEFINED: Byte = 0x76
    const val OP_LOAD_CONST_NULL: Byte = 0x77
    const val OP_LOAD_CONST_TRUE: Byte = 0x78
    const val OP_LOAD_CONST_FALSE: Byte = 0x79
    const val OP_LOAD_CONST_ZERO: Byte = 0x7a
    const val OP_START_GENERATOR: Byte = 0x86.toByte()
    const val OP_RESUME_GENERATOR: Byte = 0x87.toByte()
    const val OP_COMPLETE_GENERATOR: Byte = 0x88.toByte()
    const val OP_JMP_TRUE: Byte = 0x90.toByte()
    const val OP_JMP_TRUE_LONG: Byte = 0x91.toByte()

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

    private const val MIN_REMOTE_CONFIG_CALL2_LEN: Int = 16

    // Exact HBC v96 instruction widths indexed by opcode byte (0x00..0xbf).
    private val OPCODE_LENGTHS = intArrayOf(
        1, 10, 14, 2, 3, 8, 10, 4, 3, 9, 3, 3, 3, 3, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 3, 3, 4, 4, 3, 4, 5, 4, 5, 4, 5,
        2, 2, 2, 7, 5, 5, 5, 6, 8, 6, 8, 6, 8, 6, 8, 4,
        5, 7, 5, 7, 4, 7, 5, 5, 7, 4, 4, 4, 6, 5, 6, 4,
        4, 4, 5, 5, 6, 7, 7, 7, 7, 4, 7, 3, 2, 2, 4, 2,
        3, 1, 1, 3, 5, 7, 5, 7, 5, 7, 4, 4, 3, 6, 3, 6,
        10, 4, 6, 4, 6, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 3,
        3, 4, 3, 2, 14, 18, 1, 3, 1, 5, 7, 3, 4, 3, 2, 5,
        3, 6, 3, 6, 3, 6, 2, 5, 4, 7, 4, 7, 4, 7, 4, 7,
        4, 7, 4, 7, 4, 7, 4, 7, 4, 7, 4, 7, 4, 7, 4, 7,
        4, 7, 4, 7, 4, 7, 4, 7, 4, 7, 4, 7, 4, 7, 4, 7,
    )

    /** Describes an in-place HBC v96 bytecode mutation applied atomically within one bundle pass. */
    sealed interface Mutation {
        val label: String

        /**
         * Matches `GetById[Short|Long](rFn, rObj, getterName); LoadConstString[LongIndex](rArg,
         * configKey); Call2(rDst, rFn, rObj, rArg); Ret(rDst)` inside the unique named helper
         * function and replaces the 5-byte `Call2` instruction with `returnOpcode rDst; Ret rDst;
         * Unreachable`.
         */
        data class RemoteConfigReturnConst(
            val functionName: String,
            val getterMethodName: String,
            val configKey: String,
            val returnOpcode: Byte,
        ) : Mutation {
            override val label: String
                get() = "RemoteConfigReturnConst($functionName:$configKey)"
        }

        /**
         * Overwrites the entry point of a synchronous function identified by exact name (and
         * optional string/ID references that must appear inside its bytecode) with [replacement].
         */
        data class FunctionEarlyReturn(
            val functionName: String,
            val replacement: ByteArray,
            val requiredStrings: List<String> = emptyList(),
        ) : Mutation {
            override val label: String
                get() = "FunctionEarlyReturn($functionName)"

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is FunctionEarlyReturn) return false
                return functionName == other.functionName &&
                    replacement.contentEquals(other.replacement) &&
                    requiredStrings == other.requiredStrings
            }

            override fun hashCode(): Int {
                var result = functionName.hashCode()
                result = 31 * result + replacement.contentHashCode()
                result = 31 * result + requiredStrings.hashCode()
                return result
            }
        }

        /**
         * Overwrites the post-resume entry of a Hermes generator (`StartGenerator; ResumeGenerator
         * r0, rDone; JmpTrue[Long] rDone, +off`) identified by [functionName] and all
         * [requiredStrings] with `<returnOpcode> rDone; CompleteGenerator; Ret rDone` (5 bytes).
         */
        data class GeneratorEarlyReturn(
            val functionName: String,
            val requiredStrings: List<String>,
            val returnOpcode: Byte,
        ) : Mutation {
            override val label: String
                get() = "GeneratorEarlyReturn($functionName:$requiredStrings)"
        }

        /**
         * Rewrites the constant string argument passed to a `Call2` of `[calleeName]` inside the
         * unique synchronous function named [functionName] containing all [requiredStrings], from
         * [fromValue] to [toValue], without mutating shared string table bytes.
         */
        data class ReplaceCallStringConst(
            val functionName: String,
            val calleeName: String,
            val fromValue: String,
            val toValue: String,
            val requiredStrings: List<String> = emptyList(),
        ) : Mutation {
            override val label: String
                get() = "ReplaceCallStringConst($functionName:$calleeName:$fromValue->$toValue)"
        }
    }

    data class AppliedSite(
        val label: String,
        val functionIndex: Int,
        val patchOffset: Int,
        val byteCount: Int,
        val register: Int,
    )

    data class BatchPatchResult(
        val bytes: ByteArray,
        val appliedSites: List<AppliedSite>,
    )

    private data class FunctionMeta(
        val index: Int,
        val nameId: Int,
        val codeOffset: Int,
        val codeSize: Int,
    )

    private data class TargetPattern(
        val text: String,
        val chars: CharArray,
    )

    /**
     * Validates [bundle], applies every mutation in [mutations] in order, recomputes the trailing
     * SHA-1 integrity footer once, and returns the patched bundle plus per-site audit metadata.
     */
    fun patch(bundle: ByteArray, mutations: List<Mutation>): BatchPatchResult {
        require(mutations.isNotEmpty()) { "At least one Hermes mutation is required." }
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

        val requiredStrings = collectRequiredStrings(mutations)
        val stringIds = resolveStringIds(
            bundle = bundle,
            smallStrOff = smallStrOff.toInt(),
            ovfStrOff = ovfStrOff.toInt(),
            strStorageOff = strStorageOff.toInt(),
            stringCount = stringCount,
            overflowStringCount = overflowStringCount,
            stringStorageSize = stringStorageSize,
            targets = requiredStrings,
        )

        val wantedNameIds = buildSet {
            for (mutation in mutations) {
                when (mutation) {
                    is Mutation.RemoteConfigReturnConst -> add(stringIds.getValue(mutation.functionName))
                    is Mutation.FunctionEarlyReturn -> add(stringIds.getValue(mutation.functionName))
                    is Mutation.GeneratorEarlyReturn -> add(stringIds.getValue(mutation.functionName))
                    is Mutation.ReplaceCallStringConst -> add(stringIds.getValue(mutation.functionName))
                }
            }
        }
        val functionsByName = resolveWantedFunctions(bundle, functionCount, contentEnd, wantedNameIds)

        val output = bundle.copyOf()
        val appliedSites = ArrayList<AppliedSite>(mutations.size)

        for (mutation in mutations) {
            val site = when (mutation) {
                is Mutation.RemoteConfigReturnConst -> applyRemoteConfigReturnConst(
                    bundle = output,
                    stringIds = stringIds,
                    functionsByName = functionsByName,
                    mutation = mutation,
                )
                is Mutation.FunctionEarlyReturn -> applyFunctionEarlyReturn(
                    bundle = output,
                    stringIds = stringIds,
                    functionsByName = functionsByName,
                    mutation = mutation,
                )
                is Mutation.GeneratorEarlyReturn -> applyGeneratorEarlyReturn(
                    bundle = output,
                    stringIds = stringIds,
                    functionsByName = functionsByName,
                    mutation = mutation,
                )
                is Mutation.ReplaceCallStringConst -> applyReplaceCallStringConst(
                    bundle = output,
                    stringIds = stringIds,
                    functionsByName = functionsByName,
                    mutation = mutation,
                )
            }
            appliedSites.add(site)
        }

        val newDigest = sha1(output, contentEnd)
        System.arraycopy(newDigest, 0, output, contentEnd, SHA1_SIZE)

        return BatchPatchResult(bytes = output, appliedSites = appliedSites)
    }

    /** Convenience wrapper for applying a single [mutation]. */
    fun patch(bundle: ByteArray, mutation: Mutation): BatchPatchResult =
        patch(bundle, listOf(mutation))

    private fun collectRequiredStrings(mutations: List<Mutation>): Set<String> {
        val out = LinkedHashSet<String>()
        for (mutation in mutations) {
            when (mutation) {
                is Mutation.RemoteConfigReturnConst -> {
                    out.add(mutation.functionName)
                    out.add(mutation.getterMethodName)
                    out.add(mutation.configKey)
                }
                is Mutation.FunctionEarlyReturn -> {
                    out.add(mutation.functionName)
                    out.addAll(mutation.requiredStrings)
                }
                is Mutation.GeneratorEarlyReturn -> {
                    out.add(mutation.functionName)
                    out.addAll(mutation.requiredStrings)
                }
                is Mutation.ReplaceCallStringConst -> {
                    out.add(mutation.functionName)
                    out.add(mutation.calleeName)
                    out.add(mutation.fromValue)
                    out.add(mutation.toValue)
                    out.addAll(mutation.requiredStrings)
                }
            }
        }
        return out
    }

    private fun resolveStringIds(
        bundle: ByteArray,
        smallStrOff: Int,
        ovfStrOff: Int,
        strStorageOff: Int,
        stringCount: Int,
        overflowStringCount: Int,
        stringStorageSize: Int,
        targets: Set<String>,
    ): Map<String, Int> {
        val byLen = LinkedHashMap<Int, MutableList<TargetPattern>>()
        for (target in targets) {
            val chars = target.toCharArray()
            byLen.getOrPut(chars.size) { ArrayList(2) }.add(TargetPattern(target, chars))
        }

        val resolved = LinkedHashMap<String, Int>(targets.size * 2)
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

            if (charLen > Int.MAX_VALUE) continue
            val candidates = byLen[charLen.toInt()] ?: continue
            val startPos = strStorageOff + realOffset.toInt()
            for (candidate in candidates) {
                if (matchesCodeUnits(bundle, startPos, isUtf16, candidate.chars)) {
                    val prev = resolved.put(candidate.text, i)
                    require(prev == null) {
                        "Duplicate string table entries for '${candidate.text}' (#$prev and #$i)."
                    }
                    break
                }
            }
        }

        for (target in targets) {
            require(target in resolved) { "Missing required string '$target' in Hermes string table." }
        }
        return resolved
    }

    private fun resolveWantedFunctions(
        bundle: ByteArray,
        functionCount: Int,
        contentEnd: Int,
        wantedNameIds: Set<Int>,
    ): Map<Int, List<FunctionMeta>> {
        val grouped = LinkedHashMap<Int, MutableList<FunctionMeta>>(wantedNameIds.size * 2)
        for (id in wantedNameIds) {
            grouped[id] = ArrayList(2)
        }

        for (funcIdx in 0 until functionCount) {
            val hOff = HEADER_SIZE + funcIdx * SMALL_FUNC_HEADER_SIZE
            val w0 = i32Le(bundle, hOff)
            val w1 = i32Le(bundle, hOff + 4)
            val w2 = i32Le(bundle, hOff + 8)
            val w3 = i32Le(bundle, hOff + 12)
            val overflowed = (((w3 ushr 24) and 0xff) ushr 5 and 1) != 0

            val codeOffset: Int
            val codeSize: Int
            val nameIdx: Int

            if (!overflowed) {
                nameIdx = (w1 ushr 15) and 0x1ffff
                if (nameIdx !in grouped) continue
                codeOffset = w0 and 0x1ffffff
                codeSize = w1 and 0x7fff
                require(codeOffset >= HEADER_SIZE && codeOffset + codeSize <= contentEnd) {
                    "Bytecode range ($codeOffset + $codeSize) for function #$funcIdx out of bounds."
                }
            } else {
                val largeOffset = (((w2 and 0xffff).toLong() shl 16) or (w0 and 0xffff).toLong())
                require(largeOffset >= HEADER_SIZE && largeOffset + LARGE_FUNC_HEADER_SIZE <= contentEnd) {
                    "LargeFuncHeader offset $largeOffset for function #$funcIdx out of bounds."
                }
                val lo = largeOffset.toInt()
                val largeName = u32Le(bundle, lo + 12)
                if (largeName > Int.MAX_VALUE) continue
                nameIdx = largeName.toInt()
                if (nameIdx !in grouped) continue
                val rawOffset = u32Le(bundle, lo)
                val rawSize = u32Le(bundle, lo + 8)
                require(
                    rawOffset <= Int.MAX_VALUE &&
                        rawSize <= Int.MAX_VALUE &&
                        rawOffset >= HEADER_SIZE &&
                        rawOffset + rawSize <= contentEnd
                ) {
                    "LargeFuncHeader range ($rawOffset + $rawSize) for function #$funcIdx out of bounds."
                }
                codeOffset = rawOffset.toInt()
                codeSize = rawSize.toInt()
            }

            grouped.getValue(nameIdx).add(FunctionMeta(funcIdx, nameIdx, codeOffset, codeSize))
        }

        return grouped
    }

    private fun applyRemoteConfigReturnConst(
        bundle: ByteArray,
        stringIds: Map<String, Int>,
        functionsByName: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.RemoteConfigReturnConst,
    ): AppliedSite {
        val fnNameId = stringIds.getValue(mutation.functionName)
        val getterId = stringIds.getValue(mutation.getterMethodName)
        val keyId = stringIds.getValue(mutation.configKey)

        val candidates = functionsByName.getValue(fnNameId)
        require(candidates.size == 1) {
            "Expected 1 '${mutation.functionName}' function, found ${candidates.size}."
        }
        val fn = candidates[0]

        var matchedCallOffset = -1
        var matchedReturnRegister = -1
        var matchCount = 0

        if (fn.codeSize >= MIN_REMOTE_CONFIG_CALL2_LEN) {
            val codeEnd = fn.codeOffset + fn.codeSize
            var offset = fn.codeOffset

            while (offset < codeEnd) {
                val insLen = stepInstruction(bundle, offset, codeEnd)
                val getLen = matchGetById(bundle, offset, codeEnd, getterId)
                if (getLen <= 0) {
                    offset += insLen
                    continue
                }

                val rFn = bundle[offset + 1]
                val rObj = bundle[offset + 2]
                val next = offset + getLen
                val strMatch = matchLoadConstString(bundle, next, codeEnd, keyId)
                if (strMatch <= 0) {
                    offset += insLen
                    continue
                }

                val rArg = bundle[next + 1]
                val callOffset = next + strMatch
                if (callOffset + 7 <= codeEnd &&
                    bundle[callOffset] == OP_CALL2 &&
                    bundle[callOffset + 2] == rFn &&
                    bundle[callOffset + 3] == rObj &&
                    bundle[callOffset + 4] == rArg
                ) {
                    val rDst = bundle[callOffset + 1]
                    if (bundle[callOffset + 5] == OP_RET && bundle[callOffset + 6] == rDst) {
                        matchCount++
                        matchedCallOffset = callOffset
                        matchedReturnRegister = rDst.toInt() and 0xff
                        offset = callOffset + 7
                        continue
                    }
                }

                offset += insLen
            }
        }

        require(matchCount == 1) {
            "Expected 1 patchable Call2 site in '${mutation.functionName}' for '${mutation.configKey}', found $matchCount."
        }

        val rDstByte = matchedReturnRegister.toByte()
        bundle[matchedCallOffset] = mutation.returnOpcode
        bundle[matchedCallOffset + 1] = rDstByte
        bundle[matchedCallOffset + 2] = OP_RET
        bundle[matchedCallOffset + 3] = rDstByte
        bundle[matchedCallOffset + 4] = OP_UNREACHABLE

        return AppliedSite(
            label = mutation.label,
            functionIndex = fn.index,
            patchOffset = matchedCallOffset,
            byteCount = 5,
            register = matchedReturnRegister,
        )
    }

    private fun applyFunctionEarlyReturn(
        bundle: ByteArray,
        stringIds: Map<String, Int>,
        functionsByName: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.FunctionEarlyReturn,
    ): AppliedSite {
        require(mutation.replacement.isNotEmpty()) {
            "Replacement bytes for ${mutation.label} must not be empty."
        }
        val fnNameId = stringIds.getValue(mutation.functionName)
        val reqIds = mutation.requiredStrings.map(stringIds::getValue)
        val matching = functionsByName.getValue(fnNameId).filter { fn ->
            fn.codeSize >= mutation.replacement.size &&
                bundle[fn.codeOffset] != OP_START_GENERATOR &&
                containsAllStringRefs(bundle, fn.codeOffset, fn.codeSize, reqIds)
        }

        require(matching.size == 1) {
            "Expected 1 synchronous match for ${mutation.label}, found ${matching.size}."
        }
        val fn = matching[0]
        System.arraycopy(mutation.replacement, 0, bundle, fn.codeOffset, mutation.replacement.size)

        return AppliedSite(
            label = mutation.label,
            functionIndex = fn.index,
            patchOffset = fn.codeOffset,
            byteCount = mutation.replacement.size,
            register = 0,
        )
    }

    private fun applyGeneratorEarlyReturn(
        bundle: ByteArray,
        stringIds: Map<String, Int>,
        functionsByName: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.GeneratorEarlyReturn,
    ): AppliedSite {
        val fnNameId = stringIds.getValue(mutation.functionName)
        val reqIds = mutation.requiredStrings.map(stringIds::getValue)
        val matching = functionsByName.getValue(fnNameId).filter { fn ->
            generatorPostResumeOffset(bundle, fn) >= 0 &&
                containsAllStringRefs(bundle, fn.codeOffset, fn.codeSize, reqIds)
        }

        require(matching.size == 1) {
            "Expected 1 generator match for ${mutation.label}, found ${matching.size}."
        }
        val fn = matching[0]
        val patchOffset = generatorPostResumeOffset(bundle, fn)
        val doneReg = bundle[fn.codeOffset + 3]

        bundle[patchOffset] = mutation.returnOpcode
        bundle[patchOffset + 1] = doneReg
        bundle[patchOffset + 2] = OP_COMPLETE_GENERATOR
        bundle[patchOffset + 3] = OP_RET
        bundle[patchOffset + 4] = doneReg

        return AppliedSite(
            label = mutation.label,
            functionIndex = fn.index,
            patchOffset = patchOffset,
            byteCount = 5,
            register = doneReg.toInt() and 0xff,
        )
    }

    private fun applyReplaceCallStringConst(
        bundle: ByteArray,
        stringIds: Map<String, Int>,
        functionsByName: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.ReplaceCallStringConst,
    ): AppliedSite {
        require(mutation.fromValue != mutation.toValue) {
            "Replacement string for ${mutation.label} must differ from source string."
        }
        val fnNameId = stringIds.getValue(mutation.functionName)
        val calleeId = stringIds.getValue(mutation.calleeName)
        val fromId = stringIds.getValue(mutation.fromValue)
        val toId = stringIds.getValue(mutation.toValue)
        val reqIds = mutation.requiredStrings.map(stringIds::getValue)

        val candidates = functionsByName.getValue(fnNameId).filter { fn ->
            fn.codeSize >= MIN_CALL_STRING_ARG_LEN &&
                bundle[fn.codeOffset] != OP_START_GENERATOR &&
                containsAllStringRefs(bundle, fn.codeOffset, fn.codeSize, reqIds)
        }
        require(candidates.size == 1) {
            "Expected 1 synchronous match for ${mutation.label}, found ${candidates.size}."
        }
        val fn = candidates[0]

        var matchedOperandOffset = -1
        var matchedOperandWidth = 0
        var matchedArgReg = -1
        var matchCount = 0

        val codeEnd = fn.codeOffset + fn.codeSize
        var offset = fn.codeOffset
        while (offset < codeEnd) {
            val insLen = stepInstruction(bundle, offset, codeEnd)

            // Indirect calls like `(0, _react.useState)('front')` pass `undefined` as Call2's `this`
            // register (`bundle[callOff + 3]`), so validate `func == rFn` and `arg == rArg`.
            // Pattern A: GetById*(rFn, rObj, callee) -> LoadConstString*(rArg, from) -> Call2(rDst, rFn, rThis, rArg)
            val getLenA = matchGetById(bundle, offset, codeEnd, calleeId)
            if (getLenA > 0) {
                val rFn = bundle[offset + 1]
                val strOff = offset + getLenA
                val strLen = matchLoadConstString(bundle, strOff, codeEnd, fromId)
                if (strLen > 0) {
                    val rArg = bundle[strOff + 1]
                    val callOff = strOff + strLen
                    if (rArg != rFn &&
                        callOff + 5 <= codeEnd &&
                        bundle[callOff] == OP_CALL2 &&
                        bundle[callOff + 2] == rFn &&
                        bundle[callOff + 4] == rArg
                    ) {
                        matchCount++
                        matchedOperandOffset = strOff + 2
                        matchedOperandWidth = if (bundle[strOff] == OP_LOAD_CONST_STRING_LONG_INDEX) 4 else 2
                        matchedArgReg = rArg.toInt() and 0xff
                        offset = callOff + 5
                        continue
                    }
                }
            }

            // Pattern B: LoadConstString*(rArg, from) -> GetById*(rFn, rObj, callee) -> Call2(rDst, rFn, rThis, rArg)
            val strLenB = matchLoadConstString(bundle, offset, codeEnd, fromId)
            if (strLenB > 0) {
                val rArg = bundle[offset + 1]
                val getOff = offset + strLenB
                val getLenB = matchGetById(bundle, getOff, codeEnd, calleeId)
                if (getLenB > 0) {
                    val rFn = bundle[getOff + 1]
                    val callOff = getOff + getLenB
                    if (rArg != rFn &&
                        callOff + 5 <= codeEnd &&
                        bundle[callOff] == OP_CALL2 &&
                        bundle[callOff + 2] == rFn &&
                        bundle[callOff + 4] == rArg
                    ) {
                        matchCount++
                        matchedOperandOffset = offset + 2
                        matchedOperandWidth = if (bundle[offset] == OP_LOAD_CONST_STRING_LONG_INDEX) 4 else 2
                        matchedArgReg = rArg.toInt() and 0xff
                        offset = callOff + 5
                        continue
                    }
                }
            }

            offset += insLen
        }

        require(matchCount == 1) {
            "Expected 1 patchable Call2 site in ${mutation.label}, found $matchCount."
        }
        if (matchedOperandWidth == 2) {
            require(toId in 0..0xffff) {
                "String ID $toId for '${mutation.toValue}' exceeds 16-bit LoadConstString range."
            }
            writeU16Le(bundle, matchedOperandOffset, toId)
        } else {
            writeU32Le(bundle, matchedOperandOffset, toId.toLong())
        }

        return AppliedSite(
            label = mutation.label,
            functionIndex = fn.index,
            patchOffset = matchedOperandOffset,
            byteCount = matchedOperandWidth,
            register = matchedArgReg,
        )
    }

    private fun generatorPostResumeOffset(bundle: ByteArray, fn: FunctionMeta): Int {
        val s = fn.codeOffset
        if (fn.codeSize < 12) return -1
        if (bundle[s] != OP_START_GENERATOR || bundle[s + 1] != OP_RESUME_GENERATOR) return -1
        val rDone = bundle[s + 3]
        return when (bundle[s + 4]) {
            OP_JMP_TRUE -> {
                if (bundle[s + 6] != rDone) -1 else s + 7
            }
            OP_JMP_TRUE_LONG -> {
                // JmpTrueLong layout: opcode (1) + rel32 (4) + target register (1).
                if (fn.codeSize < 15 || bundle[s + 9] != rDone) -1 else s + 10
            }
            else -> -1
        }
    }

    private fun matchGetById(bundle: ByteArray, pos: Int, codeEnd: Int, expectedId: Int): Int {
        return when (bundle[pos]) {
            OP_GET_BY_ID_SHORT -> if (pos + 5 <= codeEnd && (bundle[pos + 4].toInt() and 0xff) == expectedId) 5 else -1
            OP_GET_BY_ID -> if (pos + 6 <= codeEnd && u16Le(bundle, pos + 4) == expectedId) 6 else -1
            OP_GET_BY_ID_LONG -> if (pos + 8 <= codeEnd && u32Le(bundle, pos + 4) == expectedId.toLong()) 8 else -1
            else -> -1
        }
    }

    private fun matchLoadConstString(bundle: ByteArray, pos: Int, codeEnd: Int, expectedId: Int): Int {
        if (pos >= codeEnd) return -1
        return when (bundle[pos]) {
            OP_LOAD_CONST_STRING -> if (pos + 4 <= codeEnd && u16Le(bundle, pos + 2) == expectedId) 4 else -1
            OP_LOAD_CONST_STRING_LONG_INDEX ->
                if (pos + 6 <= codeEnd && u32Le(bundle, pos + 2) == expectedId.toLong()) 6 else -1
            else -> -1
        }
    }

    private fun containsAllStringRefs(
        bundle: ByteArray,
        codeOffset: Int,
        codeSize: Int,
        requiredIds: List<Int>,
    ): Boolean {
        if (requiredIds.isEmpty()) return true
        val codeEnd = codeOffset + codeSize
        val remaining = LinkedHashSet(requiredIds)

        var pos = codeOffset
        while (pos < codeEnd && remaining.isNotEmpty()) {
            val insLen = stepInstruction(bundle, pos, codeEnd)
            val strId = extractStringId(bundle, pos, codeEnd)
            if (strId != null) {
                remaining.remove(strId)
            }
            pos += insLen
        }
        return remaining.isEmpty()
    }

    private fun stepInstruction(bundle: ByteArray, pos: Int, codeEnd: Int): Int {
        val opId = bundle[pos].toInt() and 0xff
        if (opId !in OPCODE_LENGTHS.indices) return 1
        val len = OPCODE_LENGTHS[opId]
        return if (pos + len <= codeEnd) len else 1
    }

    private fun extractStringId(bundle: ByteArray, pos: Int, codeEnd: Int): Int? {
        return when (bundle[pos]) {
            OP_GET_BY_ID_SHORT -> if (pos + 5 <= codeEnd) bundle[pos + 4].toInt() and 0xff else null
            OP_GET_BY_ID, OP_TRY_GET_BY_ID, OP_PUT_BY_ID, OP_TRY_PUT_BY_ID ->
                if (pos + 6 <= codeEnd) u16Le(bundle, pos + 4) else null
            OP_GET_BY_ID_LONG, OP_TRY_GET_BY_ID_LONG, OP_PUT_BY_ID_LONG, OP_TRY_PUT_BY_ID_LONG ->
                if (pos + 8 <= codeEnd) u32Le(bundle, pos + 4).takeIf { it <= Int.MAX_VALUE }?.toInt() else null
            OP_PUT_NEW_OWN_BY_ID_SHORT -> if (pos + 4 <= codeEnd) bundle[pos + 3].toInt() and 0xff else null
            OP_PUT_NEW_OWN_BY_ID, OP_PUT_NEW_OWN_NE_BY_ID ->
                if (pos + 5 <= codeEnd) u16Le(bundle, pos + 3) else null
            OP_PUT_NEW_OWN_BY_ID_LONG, OP_PUT_NEW_OWN_NE_BY_ID_LONG ->
                if (pos + 7 <= codeEnd) u32Le(bundle, pos + 3).takeIf { it <= Int.MAX_VALUE }?.toInt() else null
            OP_LOAD_CONST_STRING -> if (pos + 4 <= codeEnd) u16Le(bundle, pos + 2) else null
            OP_LOAD_CONST_STRING_LONG_INDEX ->
                if (pos + 6 <= codeEnd) u32Le(bundle, pos + 2).takeIf { it <= Int.MAX_VALUE }?.toInt() else null
            else -> null
        }
    }

    private fun matchesCodeUnits(
        bundle: ByteArray,
        startPos: Int,
        isUtf16: Boolean,
        chars: CharArray,
    ): Boolean {
        return if (!isUtf16) {
            for (k in chars.indices) {
                val expected = chars[k].code
                if (expected > 0xff || (bundle[startPos + k].toInt() and 0xff) != expected) {
                    return false
                }
            }
            true
        } else {
            for (k in chars.indices) {
                val expected = chars[k].code
                if (u16Le(bundle, startPos + k * 2) != expected) {
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

    private const val MIN_CALL_STRING_ARG_LEN = 14

    private fun writeU16Le(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xff).toByte()
    }

    private fun writeU32Le(bytes: ByteArray, offset: Int, value: Long) {
        bytes[offset] = (value and 0xffL).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xffL).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xffL).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xffL).toByte()
    }

    private fun sha1(bytes: ByteArray, length: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-1")
        digest.update(bytes, 0, length)
        return digest.digest()
    }
}
