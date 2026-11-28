// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Shared Hermes HBC v96 parser and patcher

package io.github.ryuuseiakira.locket.patches.shared

import java.security.MessageDigest

/**
 * Shared pure-Kotlin Hermes bytecode (HBC v96) parser, verifier, and patcher for
 * `assets/index.android.bundle`.
 *
 * Attachment: Hermes HBC v96 buffer (`assets/index.android.bundle`) parsed by header, function
 * table, string table, and trailing SHA-1 integrity footer.
 * Mechanism: Validates magic, version 96, exact `fileLength`, and trailing SHA-1 digest, maps
 * needed string table indices and function headers (`SmallFuncHeader` and `LargeFuncHeader`),
 * applies length-preserving in-place rewrites or EOF-appended function relocations with header
 * `fileLength` / `SmallFuncHeader` updates, and recomputes the trailing SHA-1 footer.
 * Constraint: In-place writes preserve all offsets; relocated functions must have no exception
 * handlers or debug info, remain within `SmallFuncHeader` bounds, and pass unambiguous structural
 * and register-frame verification.
 */
object HermesHbc96 {
    const val BUNDLE_PATH: String = "assets/index.android.bundle"

    const val HBC_MAGIC: Long = 0x1f1903c103bc1fc6L
    const val HBC_VERSION: Int = 96
    const val HEADER_SIZE: Int = 128
    const val SHA1_SIZE: Int = 20

    const val OP_UNREACHABLE: Byte = 0x00
    const val OP_NEW_OBJECT: Byte = 0x03
    const val OP_MOV: Byte = 0x08
    const val OP_GET_ENVIRONMENT: Byte = 0x29
    const val OP_LOAD_FROM_ENVIRONMENT: Byte = 0x2e
    const val OP_CREATE_ENVIRONMENT: Byte = 0x32
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
    const val OP_CALL1: Byte = 0x51
    const val OP_CALL2: Byte = 0x53
    const val OP_CALL3: Byte = 0x54
    const val OP_RET: Byte = 0x5c
    const val OP_CREATE_CLOSURE: Byte = 0x64
    const val OP_CREATE_CLOSURE_LONG_INDEX: Byte = 0x65
    const val OP_CREATE_GENERATOR_CLOSURE: Byte = 0x66
    const val OP_CREATE_GENERATOR_CLOSURE_LONG_INDEX: Byte = 0x67
    const val OP_LOAD_PARAM: Byte = 0x6c
    const val OP_LOAD_CONST_INT: Byte = 0x6f
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
    const val OP_CREATE_GENERATOR: Byte = 0x89.toByte()
    const val OP_CREATE_GENERATOR_LONG_INDEX: Byte = 0x8a.toByte()
    const val OP_JMP: Byte = 0x8e.toByte()
    const val OP_JMP_LONG: Byte = 0x8f.toByte()
    const val OP_JMP_TRUE: Byte = 0x90.toByte()
    const val OP_JMP_TRUE_LONG: Byte = 0x91.toByte()
    const val OP_JGREATER: Byte = 0xa8.toByte()
    const val OP_JGREATER_LONG: Byte = 0xa9.toByte()
    const val OP_JEQUAL: Byte = 0xb8.toByte()
    const val OP_JEQUAL_LONG: Byte = 0xb9.toByte()
    const val OP_JSTRICT_NOT_EQUAL: Byte = 0xbe.toByte()
    const val OP_JSTRICT_NOT_EQUAL_LONG: Byte = 0xbf.toByte()

    private const val SMALL_FUNC_HEADER_SIZE: Int = 16
    private const val LARGE_FUNC_HEADER_SIZE: Int = 32
    private const val OVERFLOW_STRING_ENTRY_SIZE: Int = 8
    private const val FLAG_HAS_EXCEPTION_HANDLER: Int = 0x08
    private const val FLAG_HAS_DEBUG_INFO: Int = 0x10
    private const val FLAG_OVERFLOWED: Int = 0x20
    private const val MAX_SMALL_OFFSET: Int = 0x1ffffff
    private const val MAX_SMALL_BYTECODE_SIZE: Int = 0x7fff
    private const val MAX_SMALL_FRAME_SIZE: Int = 0x7f
    private const val CALLER_OUTGOING_REGS_RESERVE: Int = 8 // StackFrameLayout: 6 header + this + arg0..
    private const val ORIGINAL_PICKER_MAX_FILE_BYTES: Int = 104_857_600 // 100 MiB in openCameraRoll
    const val DEFAULT_VIDEO_PICKER_MAX_FILE_BYTES: Int = 536_870_912 // 512 MiB pre-transcode ceiling

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

        /**
         * Enables camera-roll video selection (`MediaTypeOptions.All`), raises the pre-transcode
         * file-size ceiling to [maxFileSizeBytes], tags `fileType: asset.type` in `openCameraRoll`,
         * and routes picked videos into `Home`'s `onRecordingFinished` pipeline via a relocated
         * `onSuccess` closure body.
         */
        data class EnableCameraRollVideoUpload(
            val maxFileSizeBytes: Int = DEFAULT_VIDEO_PICKER_MAX_FILE_BYTES,
        ) : Mutation {
            init {
                require(maxFileSizeBytes > 0) {
                    "maxFileSizeBytes must be positive (got $maxFileSizeBytes)."
                }
            }

            override val label: String
                get() = "EnableCameraRollVideoUpload($maxFileSizeBytes)"
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
        val paramCount: Int,
        val infoOffset: Int,
        val frameSize: Int,
        val environmentSize: Int,
        val highestReadCacheIndex: Int,
        val highestWriteCacheIndex: Int,
        val flags: Int,
        val overflowed: Boolean,
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
                    is Mutation.EnableCameraRollVideoUpload -> {
                        add(stringIds.getValue(""))
                        add(stringIds.getValue("?anon_0_"))
                        add(stringIds.getValue("Home"))
                    }
                }
            }
        }
        val functionsByName = resolveWantedFunctions(bundle, functionCount, contentEnd, wantedNameIds)

        var output = bundle.copyOf()
        var currentContentEnd = contentEnd
        val appliedSites = ArrayList<AppliedSite>(mutations.size)

        for (mutation in mutations) {
            when (mutation) {
                is Mutation.RemoteConfigReturnConst -> appliedSites.add(
                    applyRemoteConfigReturnConst(
                        bundle = output,
                        stringIds = stringIds,
                        functionsByName = functionsByName,
                        mutation = mutation,
                    ),
                )
                is Mutation.FunctionEarlyReturn -> appliedSites.add(
                    applyFunctionEarlyReturn(
                        bundle = output,
                        stringIds = stringIds,
                        functionsByName = functionsByName,
                        mutation = mutation,
                    ),
                )
                is Mutation.GeneratorEarlyReturn -> appliedSites.add(
                    applyGeneratorEarlyReturn(
                        bundle = output,
                        stringIds = stringIds,
                        functionsByName = functionsByName,
                        mutation = mutation,
                    ),
                )
                is Mutation.ReplaceCallStringConst -> appliedSites.add(
                    applyReplaceCallStringConst(
                        bundle = output,
                        stringIds = stringIds,
                        functionsByName = functionsByName,
                        mutation = mutation,
                    ),
                )
                is Mutation.EnableCameraRollVideoUpload -> {
                    val result = applyEnableCameraRollVideoUpload(
                        bundle = output,
                        contentEnd = currentContentEnd,
                        functionCount = functionCount,
                        stringIds = stringIds,
                        functionsByName = functionsByName,
                        mutation = mutation,
                    )
                    output = result.bytes
                    currentContentEnd = result.contentEnd
                    appliedSites.addAll(result.sites)
                }
            }
        }

        val newDigest = sha1(output, currentContentEnd)
        System.arraycopy(newDigest, 0, output, currentContentEnd, SHA1_SIZE)

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
                is Mutation.EnableCameraRollVideoUpload -> {
                    out.addAll(VIDEO_UPLOAD_REQUIRED_STRINGS)
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
            val w1 = i32Le(bundle, hOff + 4)
            val w3 = i32Le(bundle, hOff + 12)
            val overflowed = (((w3 ushr 24) and 0xff) and FLAG_OVERFLOWED) != 0

            val nameIdx = if (!overflowed) {
                (w1 ushr 15) and 0x1ffff
            } else {
                val w0 = i32Le(bundle, hOff)
                val w2 = i32Le(bundle, hOff + 8)
                val largeOffset = (((w2 and 0xffff).toLong() shl 16) or (w0 and 0xffff).toLong())
                require(largeOffset >= HEADER_SIZE && largeOffset + LARGE_FUNC_HEADER_SIZE <= contentEnd) {
                    "LargeFuncHeader offset $largeOffset for function #$funcIdx out of bounds."
                }
                val largeName = u32Le(bundle, largeOffset.toInt() + 12)
                if (largeName > Int.MAX_VALUE) continue
                largeName.toInt()
            }
            if (nameIdx !in grouped) continue
            grouped.getValue(nameIdx).add(readFunctionMeta(bundle, funcIdx, contentEnd))
        }

        return grouped
    }

    private fun readFunctionMeta(
        bundle: ByteArray,
        funcIdx: Int,
        contentEnd: Int,
    ): FunctionMeta {
        val hOff = HEADER_SIZE + funcIdx * SMALL_FUNC_HEADER_SIZE
        val w0 = i32Le(bundle, hOff)
        val w1 = i32Le(bundle, hOff + 4)
        val w2 = i32Le(bundle, hOff + 8)
        val w3 = i32Le(bundle, hOff + 12)
        val flags = (w3 ushr 24) and 0xff
        val overflowed = (flags and FLAG_OVERFLOWED) != 0

        if (!overflowed) {
            val codeOffset = w0 and 0x1ffffff
            val codeSize = w1 and 0x7fff
            require(codeOffset >= HEADER_SIZE && codeOffset + codeSize <= contentEnd) {
                "Bytecode range ($codeOffset + $codeSize) for function #$funcIdx out of bounds."
            }
            return FunctionMeta(
                index = funcIdx,
                nameId = (w1 ushr 15) and 0x1ffff,
                codeOffset = codeOffset,
                codeSize = codeSize,
                paramCount = (w0 ushr 25) and 0x7f,
                infoOffset = w2 and 0x1ffffff,
                frameSize = (w2 ushr 25) and 0x7f,
                environmentSize = w3 and 0xff,
                highestReadCacheIndex = (w3 ushr 8) and 0xff,
                highestWriteCacheIndex = (w3 ushr 16) and 0xff,
                flags = flags,
                overflowed = false,
            )
        }

        val largeOffset = (((w2 and 0xffff).toLong() shl 16) or (w0 and 0xffff).toLong())
        require(largeOffset >= HEADER_SIZE && largeOffset + LARGE_FUNC_HEADER_SIZE <= contentEnd) {
            "LargeFuncHeader offset $largeOffset for function #$funcIdx out of bounds."
        }
        val lo = largeOffset.toInt()
        val rawOffset = u32Le(bundle, lo)
        val rawParamCount = u32Le(bundle, lo + 4)
        val rawSize = u32Le(bundle, lo + 8)
        val rawName = u32Le(bundle, lo + 12)
        val rawInfoOffset = u32Le(bundle, lo + 16)
        val rawFrameSize = u32Le(bundle, lo + 20)
        val rawEnvSize = u32Le(bundle, lo + 24)
        val rawTail = i32Le(bundle, lo + 28)
        require(
            rawOffset <= Int.MAX_VALUE &&
                rawSize <= Int.MAX_VALUE &&
                rawName <= Int.MAX_VALUE &&
                rawOffset >= HEADER_SIZE &&
                rawOffset + rawSize <= contentEnd
        ) {
            "LargeFuncHeader range ($rawOffset + $rawSize) for function #$funcIdx out of bounds."
        }
        return FunctionMeta(
            index = funcIdx,
            nameId = rawName.toInt(),
            codeOffset = rawOffset.toInt(),
            codeSize = rawSize.toInt(),
            paramCount = rawParamCount.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            infoOffset = rawInfoOffset.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            frameSize = rawFrameSize.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            environmentSize = rawEnvSize.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            highestReadCacheIndex = rawTail and 0xff,
            highestWriteCacheIndex = (rawTail ushr 8) and 0xff,
            flags = (rawTail ushr 16) and 0xff,
            overflowed = true,
        )
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

    private data class VideoUploadOutcome(
        val bytes: ByteArray,
        val contentEnd: Int,
        val sites: List<AppliedSite>,
    )

    private data class GetByIdMatch(
        val dstReg: Int,
        val objReg: Int,
        val cacheIdx: Int,
        val stringId: Int,
        val idOffset: Int,
        val idWidth: Int,
        val len: Int,
    )

    private data class PutByIdMatch(
        val objReg: Int,
        val valReg: Int,
        val stringId: Int,
        val len: Int,
    )

    private data class PutNewOwnMatch(
        val objReg: Int,
        val valReg: Int,
        val stringId: Int,
        val len: Int,
    )

    private data class ClosureMatch(
        val dstReg: Int,
        val envReg: Int,
        val funcIdx: Int,
        val isGenerator: Boolean,
        val len: Int,
    )

    private data class JumpMatch(
        val targetRelPc: Int,
        val isConditional: Boolean,
        val len: Int,
    )

    private class RegAccess(
        val writes: IntArray,
        val reads: IntArray,
        val len: Int,
    )

    private class LoadEnvMatch(
        val dstReg: Int,
        val envReg: Int,
        val len: Int,
    )

    private class StageCBlocks(
        val startLoadingOff: Int,
        val mediaProcessingEnd: Int,
        val homeEnvReg: Int,
        val undefThisReg: Int,
    )

    private fun applyEnableCameraRollVideoUpload(
        bundle: ByteArray,
        contentEnd: Int,
        functionCount: Int,
        stringIds: Map<String, Int>,
        functionsByName: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.EnableCameraRollVideoUpload,
    ): VideoUploadOutcome {
        val emptyStrId = stringIds.getValue("")
        val anonNameId = stringIds.getValue("?anon_0_")
        val homeNameId = stringIds.getValue("Home")

        var currentBytes = bundle
        var currentEnd = contentEnd
        val sites = ArrayList<AppliedSite>(4)

        // Stage A: expand picker mediaTypes from MediaTypeOptions.Images -> MediaTypeOptions.All.
        sites.add(
            patchCameraRollMediaTypesAll(
                bundle = currentBytes,
                candidates = functionsByName.getValue(emptyStrId),
                stringIds = stringIds,
            ),
        )

        // Stage B: raise pre-transcode picker size limit and attach fileType: asset.type.
        sites.addAll(
            patchOpenCameraRollGenerator(
                bundle = currentBytes,
                candidates = functionsByName.getValue(anonNameId),
                stringIds = stringIds,
                maxFileSizeBytes = mutation.maxFileSizeBytes,
            ),
        )

        // Stage C: locate Home -> onSuccess + onRecordingFinished factory -> append relocated body.
        val stageC = patchHomeOnSuccessVideoRouting(
            bundle = currentBytes,
            contentEnd = currentEnd,
            functionCount = functionCount,
            homeCandidates = functionsByName.getValue(homeNameId),
            stringIds = stringIds,
        )
        currentBytes = stageC.bytes
        currentEnd = stageC.contentEnd
        sites.addAll(stageC.sites)

        return VideoUploadOutcome(bytes = currentBytes, contentEnd = currentEnd, sites = sites)
    }

    private fun patchCameraRollMediaTypesAll(
        bundle: ByteArray,
        candidates: List<FunctionMeta>,
        stringIds: Map<String, Int>,
    ): AppliedSite {
        val mediaTypeOptionsId = stringIds.getValue("MediaTypeOptions")
        val imagesId = stringIds.getValue("Images")
        val allId = stringIds.getValue("All")
        val mediaTypesId = stringIds.getValue("mediaTypes")
        val required = listOf(
            stringIds.getValue("useCameraRoll"),
            stringIds.getValue("getFileSize"),
            mediaTypeOptionsId,
            imagesId,
            mediaTypesId,
        )

        val matchedFuncs = candidates.filter { containsAllStringRefs(bundle, it.codeOffset, it.codeSize, required) }
        require(matchedFuncs.size == 1) {
            "Expected 1 useCameraRoll initializer function, found ${matchedFuncs.size}."
        }
        val fn = matchedFuncs.single()
        val codeEnd = fn.codeOffset + fn.codeSize

        var matchCount = 0
        var patchOff = -1
        var patchWidth = 0
        var patchReg = -1

        var pos = fn.codeOffset
        while (pos < codeEnd) {
            val g1 = decodeGetById(bundle, pos, codeEnd)
            if (g1 != null && g1.stringId == mediaTypeOptionsId) {
                val p2 = pos + g1.len
                val g2 = decodeGetById(bundle, p2, codeEnd)
                if (g2 != null && g2.objReg == g1.dstReg && g2.stringId == imagesId) {
                    val p3 = p2 + g2.len
                    val put = decodePutById(bundle, p3, codeEnd)
                    if (put != null && put.valReg == g2.dstReg && put.stringId == mediaTypesId) {
                        matchCount++
                        patchOff = g2.idOffset
                        patchWidth = g2.idWidth
                        patchReg = g2.dstReg
                    }
                }
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }

        require(matchCount == 1) {
            "Expected 1 MediaTypeOptions.Images -> mediaTypes site in fn#${fn.index}, found $matchCount."
        }
        writeStringIdOperand(bundle, patchOff, patchWidth, allId, "All")

        return AppliedSite(
            label = "EnableCameraRollVideoUpload:MediaTypeOptions.All",
            functionIndex = fn.index,
            patchOffset = patchOff,
            byteCount = patchWidth,
            register = patchReg,
        )
    }

    private fun patchOpenCameraRollGenerator(
        bundle: ByteArray,
        candidates: List<FunctionMeta>,
        stringIds: Map<String, Int>,
        maxFileSizeBytes: Int,
    ): List<AppliedSite> {
        val reqPermsId = stringIds.getValue("requestMediaLibraryPermissionsAsync")
        val launchPickerId = stringIds.getValue("launchImageLibraryAsync")
        val errMsgId = stringIds.getValue("too_large_file_error_message")
        val logTagId = stringIds.getValue("useCameraRoll - openCameraRoll")
        val mediaTypesId = stringIds.getValue("MediaTypes")
        val camRollImgId = stringIds.getValue("cameraRollImage")
        val typeId = stringIds.getValue("type")
        val fileTypeId = stringIds.getValue("fileType")
        val uriId = stringIds.getValue("uri")
        val required = listOf(reqPermsId, launchPickerId, errMsgId, logTagId, mediaTypesId, camRollImgId, typeId)

        val matchedFuncs = candidates.filter { containsAllStringRefs(bundle, it.codeOffset, it.codeSize, required) }
        require(matchedFuncs.size == 1) {
            "Expected 1 openCameraRoll generator function, found ${matchedFuncs.size}."
        }
        val fn = matchedFuncs.single()
        require(!fn.overflowed) {
            "openCameraRoll fn#${fn.index} unexpectedly uses overflowed header."
        }
        val codeEnd = fn.codeOffset + fn.codeSize

        // 1. Rewrite 100 MiB (104_857_600) LoadConstInt threshold in-place.
        var sizeMatches = 0
        var sizeImmOff = -1
        var sizeReg = -1

        var pos = fn.codeOffset
        while (pos < codeEnd) {
            if (bundle[pos] == OP_LOAD_CONST_INT && pos + 6 <= codeEnd) {
                val imm = i32Le(bundle, pos + 2)
                if (imm == ORIGINAL_PICKER_MAX_FILE_BYTES) {
                    val reg = bundle[pos + 1].toInt() and 0xff
                    val nextPos = pos + 6
                    if (isJGreaterWithReg(bundle, nextPos, codeEnd, reg)) {
                        sizeMatches++
                        sizeImmOff = pos + 2
                        sizeReg = reg
                    }
                }
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }
        require(sizeMatches == 1) {
            "Expected 1 max-file-size check ($ORIGINAL_PICKER_MAX_FILE_BYTES) in openCameraRoll fn#${fn.index}, found $sizeMatches."
        }
        writeU32Le(bundle, sizeImmOff, maxFileSizeBytes.toLong())

        // 2. Rewrite `env[slot].MediaTypes.cameraRollImage` -> `cameraRollImage` + `fileType: asset.type`.
        var typeMatches = 0
        var replaceStart = -1
        var replaceEnd = -1
        var rType = -1
        var rPayload = -1
        var rAsset = -1

        pos = fn.codeOffset
        while (pos < codeEnd) {
            val envLoad = decodeLoadFromEnvironment(bundle, pos, codeEnd)
            if (envLoad != null) {
                val rCandidate = envLoad.dstReg
                val p2 = pos + envLoad.len
                val g1 = decodeGetById(bundle, p2, codeEnd)
                if (g1 != null && g1.dstReg == rCandidate && g1.objReg == rCandidate && g1.stringId == mediaTypesId) {
                    val p3 = p2 + g1.len
                    val g2 = decodeGetById(bundle, p3, codeEnd)
                    if (g2 != null && g2.dstReg == rCandidate && g2.objReg == rCandidate && g2.stringId == camRollImgId) {
                        val p4 = p3 + g2.len
                        val putType = decodePutNewOwnById(bundle, p4, codeEnd)
                        if (putType != null && putType.valReg == rCandidate && putType.stringId == typeId) {
                            val assetReg = findAssetRegAfterType(bundle, p4 + putType.len, codeEnd, uriId)
                            if (assetReg >= 0) {
                                typeMatches++
                                replaceStart = pos
                                replaceEnd = p4
                                rType = rCandidate
                                rPayload = putType.objReg
                                rAsset = assetReg
                            }
                        }
                    }
                }
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }
        require(typeMatches == 1) {
            "Expected 1 cameraRollImage payload construction site in openCameraRoll fn#${fn.index}, found $typeMatches."
        }
        val windowLen = replaceEnd - replaceStart
        require(windowLen >= MIN_CALL_STRING_ARG_LEN) {
            "openCameraRoll rewrite window ($windowLen bytes) too short."
        }
        require(!hasBranchIntoRange(bundle, fn, replaceStart + 1, replaceEnd)) {
            "openCameraRoll jump lands inside [$replaceStart, $replaceEnd)."
        }

        val maxLocalRegs = fn.frameSize - CALLER_OUTGOING_REGS_RESERVE
        require(maxLocalRegs > 0 && rType < maxLocalRegs && rPayload < maxLocalRegs && rAsset < maxLocalRegs) {
            "openCameraRoll fn#${fn.index} frameSize (${fn.frameSize}) violates outgoing register reserve."
        }

        val rScratch = findDeadLocalRegister(
            bundle = bundle,
            fn = fn,
            fromPcAbs = replaceEnd,
            maxLocalRegs = maxLocalRegs,
            excluded = setOf(rType, rPayload, rAsset),
        )
        val newReadCacheIdx = fn.highestReadCacheIndex + 1
        require(newReadCacheIdx <= 0xff) {
            "openCameraRoll fn#${fn.index} read cache index overflow ($newReadCacheIdx)."
        }

        val replacement = buildOpenCameraRollTypeAndFileTypeBytes(
            windowLen = windowLen,
            rType = rType,
            rScratch = rScratch,
            rAsset = rAsset,
            rPayload = rPayload,
            camRollImgId = camRollImgId,
            readCacheIdx = newReadCacheIdx,
            typeId = typeId,
            fileTypeId = fileTypeId,
        )
        System.arraycopy(replacement, 0, bundle, replaceStart, windowLen)
        writeSmallFuncHighestReadCacheIndex(bundle, fn.index, newReadCacheIdx)

        return listOf(
            AppliedSite(
                label = "EnableCameraRollVideoUpload:MaxFileSize",
                functionIndex = fn.index,
                patchOffset = sizeImmOff,
                byteCount = 4,
                register = sizeReg,
            ),
            AppliedSite(
                label = "EnableCameraRollVideoUpload:FileTypeTag",
                functionIndex = fn.index,
                patchOffset = replaceStart,
                byteCount = windowLen,
                register = rScratch,
            ),
        )
    }

    private fun patchHomeOnSuccessVideoRouting(
        bundle: ByteArray,
        contentEnd: Int,
        functionCount: Int,
        homeCandidates: List<FunctionMeta>,
        stringIds: Map<String, Int>,
    ): VideoUploadOutcome {
        val useCameraRollId = stringIds.getValue("useCameraRoll")
        val onSuccessPropId = stringIds.getValue("onSuccess")
        val matchedHome = homeCandidates.filter {
            containsAllStringRefs(bundle, it.codeOffset, it.codeSize, listOf(useCameraRollId, onSuccessPropId))
        }
        require(matchedHome.size == 1) {
            "Expected 1 Home component function, found ${matchedHome.size}."
        }
        val homeFn = matchedHome.single()

        val onSuccessFn = resolveHomeOnSuccessClosure(
            bundle = bundle,
            homeFn = homeFn,
            functionCount = functionCount,
            contentEnd = contentEnd,
            stringIds = stringIds,
        )
        require(!onSuccessFn.overflowed) {
            "Home onSuccess fn#${onSuccessFn.index} unexpectedly uses overflowed header."
        }
        require((onSuccessFn.flags and FLAG_HAS_EXCEPTION_HANDLER) == 0) {
            "Home onSuccess fn#${onSuccessFn.index} unexpectedly carries exception handlers."
        }
        require((onSuccessFn.flags and FLAG_HAS_DEBUG_INFO) == 0) {
            "Home onSuccess fn#${onSuccessFn.index} unexpectedly carries debug info."
        }

        val factoryFn = resolveOnRecordingFinishedFactory(
            bundle = bundle,
            homeFn = homeFn,
            functionCount = functionCount,
            contentEnd = contentEnd,
            stringIds = stringIds,
        )

        val blocks = extractStageCBlocks(bundle, onSuccessFn, stringIds)
        val newBytes = buildRelocatedOnSuccessBytecode(
            bundle = bundle,
            origFn = onSuccessFn,
            factoryFnIndex = factoryFn.index,
            blocks = blocks,
            stringIds = stringIds,
        )

        val maxLocalReg = maxUsedLocalRegister(newBytes.code)
        val newFrameSize = maxOf(onSuccessFn.frameSize, maxLocalReg + 12, 16)
        require(newFrameSize <= MAX_SMALL_FRAME_SIZE) {
            "Relocated onSuccess frameSize ($newFrameSize) exceeds SmallFuncHeader max ($MAX_SMALL_FRAME_SIZE)."
        }
        require(newBytes.code.size <= MAX_SMALL_BYTECODE_SIZE) {
            "Relocated onSuccess code size (${newBytes.code.size}) exceeds SmallFuncHeader max ($MAX_SMALL_BYTECODE_SIZE)."
        }
        validateBytecodeFunction(
            code = newBytes.code,
            frameSize = newFrameSize,
            functionCount = functionCount,
        )

        val relocOffLong = align4(contentEnd.toLong())
        require(relocOffLong <= MAX_SMALL_OFFSET.toLong()) {
            "Relocated onSuccess offset ($relocOffLong) exceeds SmallFuncHeader max ($MAX_SMALL_OFFSET)."
        }
        val relocOff = relocOffLong.toInt()
        val newContentEnd = relocOff + newBytes.code.size
        val newBundleSize = newContentEnd + SHA1_SIZE

        val out = ByteArray(newBundleSize)
        System.arraycopy(bundle, 0, out, 0, contentEnd)
        System.arraycopy(newBytes.code, 0, out, relocOff, newBytes.code.size)

        writeU32Le(out, OFF_FILE_LENGTH, newBundleSize.toLong())
        writeSmallFuncRelocationHeader(
            bytes = out,
            funcIdx = onSuccessFn.index,
            orig = onSuccessFn,
            newOffset = relocOff,
            newSize = newBytes.code.size,
            newFrameSize = newFrameSize,
            newHighestReadCacheIndex = newBytes.highestReadCacheIndex,
        )

        return VideoUploadOutcome(
            bytes = out,
            contentEnd = newContentEnd,
            sites = listOf(
                AppliedSite(
                    label = "EnableCameraRollVideoUpload:HomeOnSuccess",
                    functionIndex = onSuccessFn.index,
                    patchOffset = relocOff,
                    byteCount = newBytes.code.size,
                    register = newFrameSize,
                ),
            ),
        )
    }

    private fun resolveHomeOnSuccessClosure(
        bundle: ByteArray,
        homeFn: FunctionMeta,
        functionCount: Int,
        contentEnd: Int,
        stringIds: Map<String, Int>,
    ): FunctionMeta {
        val onSuccessPropId = stringIds.getValue("onSuccess")
        val requiredOnSuccessStrings = listOf(
            stringIds.getValue(""),
            stringIds.getValue("reset"),
            stringIds.getValue("startLoading"),
            stringIds.getValue("HomeCaptureStage"),
            stringIds.getValue("MEDIA_PROCESSING"),
        )

        val regClosures = HashMap<Int, Set<Int>>()
        val candidateFuncIds = LinkedHashSet<Int>()

        val codeEnd = homeFn.codeOffset + homeFn.codeSize
        var pos = homeFn.codeOffset
        while (pos < codeEnd) {
            val op = bundle[pos]
            val closure = decodeCreateClosure(bundle, pos, codeEnd, generatorsOnly = false)
            if (closure != null) {
                regClosures[closure.dstReg] = setOf(closure.funcIdx)
                pos += closure.len
                continue
            }
            if (op == OP_MOV && pos + 3 <= codeEnd) {
                val dst = bundle[pos + 1].toInt() and 0xff
                val src = bundle[pos + 2].toInt() and 0xff
                val srcSet = regClosures[src]
                if (srcSet != null) regClosures[dst] = srcSet else regClosures.remove(dst)
                pos += 3
                continue
            }
            val call = decodeCall(bundle, pos, codeEnd)
            if (call != null) {
                val propagated = LinkedHashSet<Int>()
                for (argReg in call.argRegs) {
                    regClosures[argReg]?.let { propagated.addAll(it) }
                }
                if (propagated.isNotEmpty()) regClosures[call.dstReg] = propagated else regClosures.remove(call.dstReg)
                pos += call.len
                continue
            }
            val putOwn = decodePutNewOwnById(bundle, pos, codeEnd)
            if (putOwn != null && putOwn.stringId == onSuccessPropId) {
                regClosures[putOwn.valReg]?.let { candidateFuncIds.addAll(it) }
                pos += putOwn.len
                continue
            }
            val access = instructionRegAccess(bundle, pos, codeEnd)
            for (w in access.writes) {
                regClosures.remove(w)
            }
            pos += access.len
        }

        val verified = candidateFuncIds.mapNotNull { fid ->
            if (fid !in 0 until functionCount) return@mapNotNull null
            val meta = readFunctionMeta(bundle, fid, contentEnd)
            if (containsAllStringRefs(bundle, meta.codeOffset, meta.codeSize, requiredOnSuccessStrings)) meta else null
        }
        require(verified.size == 1) {
            "Expected 1 Home onSuccess closure matching MEDIA_PROCESSING anchors, found ${verified.size}."
        }
        return verified.single()
    }

    private fun resolveOnRecordingFinishedFactory(
        bundle: ByteArray,
        homeFn: FunctionMeta,
        functionCount: Int,
        contentEnd: Int,
        stringIds: Map<String, Int>,
    ): FunctionMeta {
        val onRecFinishedNameId = stringIds.getValue("onRecordingFinished")
        val requiredGenStrings = listOf(
            stringIds.getValue("generateCroppedVideo"),
            stringIds.getValue("Home-onRecordingFinished"),
            stringIds.getValue("video_recording_error"),
        )

        val hop1Closures = collectChildClosures(bundle, homeFn, generatorsOnly = false)
        val matches = LinkedHashMap<Int, FunctionMeta>()

        for (wrapperIdx in hop1Closures) {
            if (wrapperIdx !in 0 until functionCount) continue
            val wrapperMeta = readFunctionMeta(bundle, wrapperIdx, contentEnd)
            val hop2Closures = collectChildClosures(bundle, wrapperMeta, generatorsOnly = false)
            for (factoryIdx in hop2Closures) {
                if (factoryIdx !in 0 until functionCount || factoryIdx in matches) continue
                val factoryMeta = readFunctionMeta(bundle, factoryIdx, contentEnd)
                if (isOnRecordingFinishedFactory(
                        bundle = bundle,
                        factoryMeta = factoryMeta,
                        functionCount = functionCount,
                        contentEnd = contentEnd,
                        onRecFinishedNameId = onRecFinishedNameId,
                        requiredGenStrings = requiredGenStrings,
                    )
                ) {
                    matches[factoryIdx] = factoryMeta
                }
            }
        }

        require(matches.size == 1) {
            "Expected 1 Home onRecordingFinished factory closure (2 hops from Home), found ${matches.size}."
        }
        return matches.values.single()
    }

    private fun isOnRecordingFinishedFactory(
        bundle: ByteArray,
        factoryMeta: FunctionMeta,
        functionCount: Int,
        contentEnd: Int,
        onRecFinishedNameId: Int,
        requiredGenStrings: List<Int>,
    ): Boolean {
        val genWrappers = collectChildClosures(bundle, factoryMeta, generatorsOnly = true)
        val innerClosures = collectChildClosures(bundle, factoryMeta, generatorsOnly = false)
        if (genWrappers.isEmpty() || innerClosures.isEmpty()) return false

        val hasNamedClosure = innerClosures.any { idx ->
            idx in 0 until functionCount &&
                readFunctionMeta(bundle, idx, contentEnd).nameId == onRecFinishedNameId
        }
        if (!hasNamedClosure) return false

        val matchedGenBody = genWrappers.mapNotNull { gwIdx ->
            if (gwIdx !in 0 until functionCount) return@mapNotNull null
            val gwMeta = readFunctionMeta(bundle, gwIdx, contentEnd)
            val gens = collectChildClosures(bundle, gwMeta, generatorsOnly = null)
            gens.firstOrNull { gIdx ->
                if (gIdx !in 0 until functionCount) return@firstOrNull false
                val gMeta = readFunctionMeta(bundle, gIdx, contentEnd)
                containsAllStringRefs(bundle, gMeta.codeOffset, gMeta.codeSize, requiredGenStrings)
            }?.let { readFunctionMeta(bundle, it, contentEnd) }
        }
        if (matchedGenBody.isEmpty()) return false

        // Verify env-depth invariant: factory skips at least the 2 synthetic/wrapper frames (>= 2)
        // and the async generator body never reads outer envs at depth < 3.
        if (minGetEnvironmentDepth(bundle, factoryMeta) < 2) return false
        for (genBody in matchedGenBody) {
            if (minGetEnvironmentDepth(bundle, genBody) < 3) return false
        }
        return true
    }

    private fun minGetEnvironmentDepth(bundle: ByteArray, fn: FunctionMeta): Int {
        var minDepth = Int.MAX_VALUE
        val codeEnd = fn.codeOffset + fn.codeSize
        var pos = fn.codeOffset
        while (pos < codeEnd) {
            if (bundle[pos] == OP_GET_ENVIRONMENT && pos + 3 <= codeEnd) {
                val depth = bundle[pos + 2].toInt() and 0xff
                if (depth < minDepth) minDepth = depth
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }
        return minDepth
    }

    private fun extractStageCBlocks(
        bundle: ByteArray,
        onSuccessFn: FunctionMeta,
        stringIds: Map<String, Int>,
    ): StageCBlocks {
        val currentId = stringIds.getValue("current")
        val startLoadingId = stringIds.getValue("startLoading")
        val stageEnumId = stringIds.getValue("HomeCaptureStage")
        val mediaProcId = stringIds.getValue("MEDIA_PROCESSING")

        val base = onSuccessFn.codeOffset
        val codeEnd = base + onSuccessFn.codeSize

        var startLoadingOff = -1
        var startLoadingEnd = -1
        var homeEnvReg = -1

        var pos = base
        while (pos < codeEnd) {
            val envLoad = decodeLoadFromEnvironment(bundle, pos, codeEnd)
            if (envLoad != null) {
                val p2 = pos + envLoad.len
                val gCurr = decodeGetById(bundle, p2, codeEnd)
                if (gCurr != null && gCurr.objReg == envLoad.dstReg && gCurr.stringId == currentId) {
                    val p3 = p2 + gCurr.len
                    if (p3 + 2 <= codeEnd && bundle[p3] == OP_LOAD_CONST_NULL) {
                        val p4 = p3 + 2
                        val jEq = decodeJump(bundle, base, p4, codeEnd)
                        if (jEq != null && (bundle[p4] == OP_JEQUAL || bundle[p4] == OP_JEQUAL_LONG)) {
                            val p5 = p4 + jEq.len
                            val gStart = decodeGetById(bundle, p5, codeEnd)
                            if (gStart != null && gStart.objReg == gCurr.dstReg && gStart.stringId == startLoadingId) {
                                val p6 = p5 + gStart.len
                                val call1 = decodeCall(bundle, p6, codeEnd)
                                if (call1 != null && bundle[p6] == OP_CALL1 && call1.calleeReg == gStart.dstReg) {
                                    val candidateEnd = p6 + call1.len
                                    if (base + jEq.targetRelPc == candidateEnd) {
                                        startLoadingOff = pos - base
                                        startLoadingEnd = candidateEnd - base
                                        homeEnvReg = envLoad.envReg
                                    }
                                }
                            }
                        }
                    }
                }
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }

        require(startLoadingOff >= 0 && startLoadingEnd > startLoadingOff && homeEnvReg >= 0) {
            "Could not extract captureButtonRef.current?.startLoading() block in fn#${onSuccessFn.index}."
        }

        // Media processing block immediately follows startLoadingEnd (exact contiguity).
        pos = base + startLoadingEnd
        val envFn = decodeLoadFromEnvironment(bundle, pos, codeEnd)
        require(envFn != null && envFn.envReg == homeEnvReg) {
            "Expected setCaptureStage closure load from r$homeEnvReg after startLoading() in fn#${onSuccessFn.index}."
        }
        val pGetModEnv = pos + envFn.len
        require(pGetModEnv + 3 <= codeEnd && bundle[pGetModEnv] == OP_GET_ENVIRONMENT) {
            "Expected module GetEnvironment in MEDIA_PROCESSING block of fn#${onSuccessFn.index}."
        }
        val pLoadStage = pGetModEnv + 3
        val envStage = decodeLoadFromEnvironment(bundle, pLoadStage, codeEnd)
        require(envStage != null) {
            "Expected HomeCaptureStage module load in fn#${onSuccessFn.index}."
        }
        val pGetStage = pLoadStage + envStage.len
        val gStage = decodeGetById(bundle, pGetStage, codeEnd)
        require(gStage != null && gStage.stringId == stageEnumId) {
            "Expected GetById HomeCaptureStage in fn#${onSuccessFn.index}."
        }
        val pGetVal = pGetStage + gStage.len
        val gMediaProc = decodeGetById(bundle, pGetVal, codeEnd)
        require(gMediaProc != null && gMediaProc.stringId == mediaProcId) {
            "Expected GetById MEDIA_PROCESSING in fn#${onSuccessFn.index}."
        }
        val pCall2 = pGetVal + gMediaProc.len
        val call2 = decodeCall(bundle, pCall2, codeEnd)
        require(call2 != null && bundle[pCall2] == OP_CALL2) {
            "Expected Call2 for MEDIA_PROCESSING transition in fn#${onSuccessFn.index}."
        }
        val undefThisReg = call2.argRegs[0]
        require(undefThisReg != homeEnvReg) {
            "Expected distinct undefined-this register (got r$undefThisReg) from homeEnvReg (r$homeEnvReg) in fn#${onSuccessFn.index}."
        }
        val mediaProcEnd = (pCall2 + call2.len) - base

        // Also validate that all jumps in the original body stay within [0, origFn.codeSize).
        pos = base
        while (pos < codeEnd) {
            val jmp = decodeJump(bundle, base, pos, codeEnd)
            if (jmp != null) {
                require(jmp.targetRelPc in 0 until onSuccessFn.codeSize) {
                    "Original fn#${onSuccessFn.index} jump target ${jmp.targetRelPc} outside code bounds."
                }
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }

        return StageCBlocks(
            startLoadingOff = startLoadingOff,
            mediaProcessingEnd = mediaProcEnd,
            homeEnvReg = homeEnvReg,
            undefThisReg = undefThisReg,
        )
    }

    private data class RelocatedBytecode(
        val code: ByteArray,
        val highestReadCacheIndex: Int,
    )

    private fun buildRelocatedOnSuccessBytecode(
        bundle: ByteArray,
        origFn: FunctionMeta,
        factoryFnIndex: Int,
        blocks: StageCBlocks,
        stringIds: Map<String, Int>,
    ): RelocatedBytecode {
        val fileTypeId = stringIds.getValue("fileType")
        val videoStrId = stringIds.getValue("video")
        val uriId = stringIds.getValue("uri")
        val replaceId = stringIds.getValue("replace")
        val fileSchemeId = stringIds.getValue("file://")
        val emptyStrId = stringIds.getValue("")

        var nextCacheIdx = maxOf(origFn.highestReadCacheIndex, maxUsedReadCacheIndex(bundle, origFn)) + 1
        val cFileType = nextCacheIdx++
        val cUri = nextCacheIdx++
        val cReplace = nextCacheIdx++
        require(cReplace <= 0xff) {
            "Relocated onSuccess read cache index ($cReplace) exceeded 8-bit limit."
        }

        val buf = ByteArrayList(origFn.codeSize + 192)

        // 1. Check asset.fileType === "video"; jump directly to original onSuccess body otherwise.
        emitLoadParam(buf, reg = 1, paramIdx = 1)
        emitGetById(buf, dst = 2, obj = 1, cacheIdx = cFileType, stringId = fileTypeId)
        emitLoadConstString(buf, dst = 3, stringId = videoStrId)
        val jmpNotVideoOff = buf.size
        buf.addByte(OP_JSTRICT_NOT_EQUAL_LONG)
        buf.addI32Le(0) // Patched once original body start offset is known.
        buf.addByte(2)
        buf.addByte(3)

        // 2. Trigger original captureButtonRef.current?.startLoading() and MEDIA_PROCESSING stage.
        buf.addByte(OP_LOAD_CONST_UNDEFINED)
        buf.addByte(blocks.undefThisReg)
        buf.addByte(OP_GET_ENVIRONMENT)
        buf.addByte(blocks.homeEnvReg)
        buf.addByte(0)
        val uiBlockStart = origFn.codeOffset + blocks.startLoadingOff
        val uiBlockLen = blocks.mediaProcessingEnd - blocks.startLoadingOff
        buf.addBytes(bundle, uiBlockStart, uiBlockLen)

        // 3. Build bare filesystem path = param1.uri.replace("file://", "") and invoke onRecordingFinished.
        buf.addByte(OP_LOAD_CONST_UNDEFINED)
        buf.addByte(0)
        emitLoadParam(buf, reg = 1, paramIdx = 1)
        emitGetById(buf, dst = 1, obj = 1, cacheIdx = cUri, stringId = uriId)
        emitGetById(buf, dst = 2, obj = 1, cacheIdx = cReplace, stringId = replaceId)
        emitLoadConstString(buf, dst = 3, stringId = fileSchemeId)
        emitLoadConstString(buf, dst = 4, stringId = emptyStrId)
        // Call3 r1, r2, r1, r3, r4
        buf.addByte(OP_CALL3)
        buf.addByte(1)
        buf.addByte(2)
        buf.addByte(1)
        buf.addByte(3)
        buf.addByte(4)

        buf.addByte(OP_CREATE_ENVIRONMENT)
        buf.addByte(3)
        emitCreateClosure(buf, dst = 3, envReg = 3, funcIdx = factoryFnIndex)
        // Call1 r2, r3, r0 (factory(undefined) -> onRecordingFinished)
        buf.addByte(OP_CALL1)
        buf.addByte(2)
        buf.addByte(3)
        buf.addByte(0)
        // Call2 r0, r2, r0, r1 (onRecordingFinished(undefined, rawPath))
        buf.addByte(OP_CALL2)
        buf.addByte(0)
        buf.addByte(2)
        buf.addByte(0)
        buf.addByte(1)
        buf.addByte(OP_LOAD_CONST_UNDEFINED)
        buf.addByte(0)
        buf.addByte(OP_RET)
        buf.addByte(0)

        // 4. Original onSuccess bytecode verbatim (all internal relative jumps remain intact).
        val origStartOff = buf.size
        buf.addBytes(bundle, origFn.codeOffset, origFn.codeSize)

        val out = buf.toByteArray()
        writeU32Le(out, jmpNotVideoOff + 1, (origStartOff - jmpNotVideoOff).toLong())
        return RelocatedBytecode(code = out, highestReadCacheIndex = cReplace)
    }

    private fun buildOpenCameraRollTypeAndFileTypeBytes(
        windowLen: Int,
        rType: Int,
        rScratch: Int,
        rAsset: Int,
        rPayload: Int,
        camRollImgId: Int,
        readCacheIdx: Int,
        typeId: Int,
        fileTypeId: Int,
    ): ByteArray {
        val strChoices = if (camRollImgId <= 0xffff) listOf(4, 6) else listOf(6)
        val getChoices = buildList {
            if (typeId <= 0xff) add(5)
            if (typeId <= 0xffff) add(6)
            add(8)
        }
        val putChoices = buildList {
            if (fileTypeId <= 0xff) add(4)
            if (fileTypeId <= 0xffff) add(5)
            add(7)
        }

        for (strLen in strChoices) {
            for (getLen in getChoices) {
                for (putLen in putChoices) {
                    val coreLen = strLen + getLen + putLen
                    val slack = windowLen - coreLen
                    if (slack < 0 || slack == 1) continue

                    val out = ByteArrayList(windowLen)
                    if (strLen == 4) {
                        out.addByte(OP_LOAD_CONST_STRING)
                        out.addByte(rType)
                        out.addU16Le(camRollImgId)
                    } else {
                        out.addByte(OP_LOAD_CONST_STRING_LONG_INDEX)
                        out.addByte(rType)
                        out.addI32Le(camRollImgId)
                    }

                    when (getLen) {
                        5 -> {
                            out.addByte(OP_GET_BY_ID_SHORT)
                            out.addByte(rScratch)
                            out.addByte(rAsset)
                            out.addByte(readCacheIdx)
                            out.addByte(typeId)
                        }
                        6 -> {
                            out.addByte(OP_GET_BY_ID)
                            out.addByte(rScratch)
                            out.addByte(rAsset)
                            out.addByte(readCacheIdx)
                            out.addU16Le(typeId)
                        }
                        else -> {
                            out.addByte(OP_GET_BY_ID_LONG)
                            out.addByte(rScratch)
                            out.addByte(rAsset)
                            out.addByte(readCacheIdx)
                            out.addI32Le(typeId)
                        }
                    }

                    when (putLen) {
                        4 -> {
                            out.addByte(OP_PUT_NEW_OWN_BY_ID_SHORT)
                            out.addByte(rPayload)
                            out.addByte(rScratch)
                            out.addByte(fileTypeId)
                        }
                        5 -> {
                            out.addByte(OP_PUT_NEW_OWN_BY_ID)
                            out.addByte(rPayload)
                            out.addByte(rScratch)
                            out.addU16Le(fileTypeId)
                        }
                        else -> {
                            out.addByte(OP_PUT_NEW_OWN_BY_ID_LONG)
                            out.addByte(rPayload)
                            out.addByte(rScratch)
                            out.addI32Le(fileTypeId)
                        }
                    }

                    var rem = slack
                    if ((rem and 1) == 1) {
                        out.addByte(OP_MOV)
                        out.addByte(rScratch)
                        out.addByte(rScratch)
                        rem -= 3
                    }
                    while (rem > 0) {
                        out.addByte(OP_LOAD_CONST_UNDEFINED)
                        out.addByte(rScratch)
                        rem -= 2
                    }
                    return out.toByteArray()
                }
            }
        }
        throw IllegalArgumentException(
            "Unable to fit exact $windowLen-byte openCameraRoll replacement for string IDs " +
                "(cameraRollImage=$camRollImgId, type=$typeId, fileType=$fileTypeId).",
        )
    }

    private fun validateBytecodeFunction(
        code: ByteArray,
        frameSize: Int,
        functionCount: Int,
    ) {
        var pos = 0
        while (pos < code.size) {
            val opId = code[pos].toInt() and 0xff
            require(opId in OPCODE_LENGTHS.indices) {
                "Invalid HBC v96 opcode 0x${opId.toString(16)} at +$pos."
            }
            val len = OPCODE_LENGTHS[opId]
            require(pos + len <= code.size) {
                "Truncated instruction 0x${opId.toString(16)} at +$pos (len=$len, size=${code.size})."
            }
            val access = instructionRegAccess(code, pos, code.size)
            for (r in access.writes) {
                require(r in 0 until frameSize) {
                    "Write register r$r out of frameSize $frameSize at +$pos."
                }
            }
            for (r in access.reads) {
                require(r in 0 until frameSize) {
                    "Read register r$r out of frameSize $frameSize at +$pos."
                }
            }
            val jmp = decodeJump(code, 0, pos, code.size)
            if (jmp != null) {
                require(jmp.targetRelPc in 0 until code.size) {
                    "Jump target ${jmp.targetRelPc} at +$pos outside code size ${code.size}."
                }
            }
            val closure = decodeCreateClosure(code, pos, code.size, generatorsOnly = null)
            if (closure != null) {
                require(closure.funcIdx in 0 until functionCount) {
                    "Closure target fn#${closure.funcIdx} at +$pos exceeds functionCount $functionCount."
                }
            }
            pos += len
        }
    }

    private fun findDeadLocalRegister(
        bundle: ByteArray,
        fn: FunctionMeta,
        fromPcAbs: Int,
        maxLocalRegs: Int,
        excluded: Set<Int>,
    ): Int {
        val base = fn.codeOffset
        val codeEnd = base + fn.codeSize
        val roots = ArrayList<Int>(4)
        roots.add(fromPcAbs)
        if ((fn.flags and FLAG_HAS_EXCEPTION_HANDLER) != 0) {
            var scan = base
            while (scan < codeEnd) {
                if (bundle[scan] == 0x5d.toByte()) {
                    roots.add(scan)
                }
                scan += stepInstruction(bundle, scan, codeEnd)
            }
        }

        for (candidate in (maxLocalRegs - 1) downTo 0) {
            if (candidate in excluded) continue
            if (!canReadBeforeWrite(bundle, base, codeEnd, roots, candidate)) {
                return candidate
            }
        }
        throw IllegalArgumentException(
            "No dead scratch register available below $maxLocalRegs in fn#${fn.index}.",
        )
    }

    private fun canReadBeforeWrite(
        bundle: ByteArray,
        base: Int,
        codeEnd: Int,
        rootsAbs: List<Int>,
        targetReg: Int,
    ): Boolean {
        val visited = HashSet<Int>()
        val queue = ArrayDeque<Int>(16)
        for (r in rootsAbs) {
            if (visited.add(r)) queue.addLast(r)
        }
        while (queue.isNotEmpty()) {
            var pos = queue.removeFirst()
            while (pos in base until codeEnd) {
                val access = instructionRegAccess(bundle, pos, codeEnd)
                if (targetReg in access.reads) return true
                if (targetReg in access.writes) break

                val op = bundle[pos]
                if (op == OP_RET || op == 0x5f.toByte() || op == OP_UNREACHABLE) break
                val jmp = decodeJump(bundle, base, pos, codeEnd)
                if (jmp != null) {
                    val targetAbs = base + jmp.targetRelPc
                    if (targetAbs in base until codeEnd && visited.add(targetAbs)) {
                        queue.addLast(targetAbs)
                    }
                    if (!jmp.isConditional) break
                }
                pos += access.len
                if (!visited.add(pos)) break
            }
        }
        return false
    }

    private fun hasBranchIntoRange(
        bundle: ByteArray,
        fn: FunctionMeta,
        startAbs: Int,
        endAbs: Int,
    ): Boolean {
        val base = fn.codeOffset
        val codeEnd = base + fn.codeSize
        var pos = base
        while (pos < codeEnd) {
            val jmp = decodeJump(bundle, base, pos, codeEnd)
            if (jmp != null) {
                val absTarget = base + jmp.targetRelPc
                if (absTarget in startAbs until endAbs) return true
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }
        return false
    }

    private fun maxUsedReadCacheIndex(bundle: ByteArray, fn: FunctionMeta): Int {
        var maxIdx = 0
        val codeEnd = fn.codeOffset + fn.codeSize
        var pos = fn.codeOffset
        while (pos < codeEnd) {
            val g = decodeGetById(bundle, pos, codeEnd)
            if (g != null && g.cacheIdx > maxIdx) {
                maxIdx = g.cacheIdx
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }
        return maxIdx
    }

    private fun maxUsedLocalRegister(code: ByteArray): Int {
        var maxReg = 0
        var pos = 0
        while (pos < code.size) {
            val access = instructionRegAccess(code, pos, code.size)
            for (r in access.writes) if (r > maxReg) maxReg = r
            for (r in access.reads) if (r > maxReg) maxReg = r
            pos += access.len
        }
        return maxReg
    }

    private fun findAssetRegAfterType(bundle: ByteArray, fromPos: Int, codeEnd: Int, uriId: Int): Int {
        var pos = fromPos
        var steps = 0
        while (pos < codeEnd && steps < 12) {
            val g = decodeGetById(bundle, pos, codeEnd)
            if (g != null && g.stringId == uriId) {
                return g.objReg
            }
            if (bundle[pos] == OP_RET || decodeCall(bundle, pos, codeEnd) != null) {
                break
            }
            pos += stepInstruction(bundle, pos, codeEnd)
            steps++
        }
        return -1
    }

    private fun collectChildClosures(
        bundle: ByteArray,
        fn: FunctionMeta,
        generatorsOnly: Boolean?,
    ): List<Int> {
        val out = ArrayList<Int>(8)
        val codeEnd = fn.codeOffset + fn.codeSize
        var pos = fn.codeOffset
        while (pos < codeEnd) {
            val closure = decodeCreateClosure(bundle, pos, codeEnd, generatorsOnly)
            if (closure != null) {
                out.add(closure.funcIdx)
            }
            pos += stepInstruction(bundle, pos, codeEnd)
        }
        return out
    }

    private fun isJGreaterWithReg(bundle: ByteArray, pos: Int, codeEnd: Int, reg: Int): Boolean {
        if (pos >= codeEnd) return false
        return when (bundle[pos]) {
            OP_JGREATER -> pos + 4 <= codeEnd &&
                ((bundle[pos + 2].toInt() and 0xff) == reg || (bundle[pos + 3].toInt() and 0xff) == reg)
            OP_JGREATER_LONG -> pos + 7 <= codeEnd &&
                ((bundle[pos + 5].toInt() and 0xff) == reg || (bundle[pos + 6].toInt() and 0xff) == reg)
            else -> false
        }
    }

    private fun writeSmallFuncHighestReadCacheIndex(bundle: ByteArray, funcIdx: Int, newCacheIdx: Int) {
        val hOff = HEADER_SIZE + funcIdx * SMALL_FUNC_HEADER_SIZE
        val w3 = i32Le(bundle, hOff + 12)
        val updatedW3 = (w3 and 0xffff00ff.toInt()) or ((newCacheIdx and 0xff) shl 8)
        writeU32Le(bundle, hOff + 12, updatedW3.toLong() and 0xffffffffL)
    }

    private fun writeSmallFuncRelocationHeader(
        bytes: ByteArray,
        funcIdx: Int,
        orig: FunctionMeta,
        newOffset: Int,
        newSize: Int,
        newFrameSize: Int,
        newHighestReadCacheIndex: Int,
    ) {
        val hOff = HEADER_SIZE + funcIdx * SMALL_FUNC_HEADER_SIZE
        val w0 = (newOffset and 0x1ffffff) or ((orig.paramCount and 0x7f) shl 25)
        val w1 = (newSize and 0x7fff) or ((orig.nameId and 0x1ffff) shl 15)
        val w2 = (orig.infoOffset and 0x1ffffff) or ((newFrameSize and 0x7f) shl 25)
        val w3 = (orig.environmentSize and 0xff) or
            ((newHighestReadCacheIndex and 0xff) shl 8) or
            ((orig.highestWriteCacheIndex and 0xff) shl 16) or
            ((orig.flags and 0xff) shl 24)
        writeU32Le(bytes, hOff, w0.toLong() and 0xffffffffL)
        writeU32Le(bytes, hOff + 4, w1.toLong() and 0xffffffffL)
        writeU32Le(bytes, hOff + 8, w2.toLong() and 0xffffffffL)
        writeU32Le(bytes, hOff + 12, w3.toLong() and 0xffffffffL)
    }

    private fun writeStringIdOperand(bytes: ByteArray, offset: Int, width: Int, stringId: Int, label: String) {
        when (width) {
            1 -> {
                require(stringId in 0..0xff) { "String ID $stringId for '$label' exceeds 8-bit operand range." }
                bytes[offset] = stringId.toByte()
            }
            2 -> {
                require(stringId in 0..0xffff) { "String ID $stringId for '$label' exceeds 16-bit operand range." }
                writeU16Le(bytes, offset, stringId)
            }
            4 -> writeU32Le(bytes, offset, stringId.toLong())
            else -> throw IllegalArgumentException("Unsupported string operand width: $width.")
        }
    }

    private fun decodeGetById(bundle: ByteArray, pos: Int, codeEnd: Int): GetByIdMatch? {
        if (pos >= codeEnd) return null
        return when (bundle[pos]) {
            OP_GET_BY_ID_SHORT -> if (pos + 5 <= codeEnd) {
                GetByIdMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    objReg = bundle[pos + 2].toInt() and 0xff,
                    cacheIdx = bundle[pos + 3].toInt() and 0xff,
                    stringId = bundle[pos + 4].toInt() and 0xff,
                    idOffset = pos + 4,
                    idWidth = 1,
                    len = 5,
                )
            } else null
            OP_GET_BY_ID -> if (pos + 6 <= codeEnd) {
                GetByIdMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    objReg = bundle[pos + 2].toInt() and 0xff,
                    cacheIdx = bundle[pos + 3].toInt() and 0xff,
                    stringId = u16Le(bundle, pos + 4),
                    idOffset = pos + 4,
                    idWidth = 2,
                    len = 6,
                )
            } else null
            OP_GET_BY_ID_LONG -> if (pos + 8 <= codeEnd) {
                val sid = u32Le(bundle, pos + 4).takeIf { it <= Int.MAX_VALUE }?.toInt() ?: return null
                GetByIdMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    objReg = bundle[pos + 2].toInt() and 0xff,
                    cacheIdx = bundle[pos + 3].toInt() and 0xff,
                    stringId = sid,
                    idOffset = pos + 4,
                    idWidth = 4,
                    len = 8,
                )
            } else null
            else -> null
        }
    }

    private fun decodePutById(bundle: ByteArray, pos: Int, codeEnd: Int): PutByIdMatch? {
        if (pos >= codeEnd) return null
        return when (bundle[pos]) {
            OP_PUT_BY_ID, OP_TRY_PUT_BY_ID -> if (pos + 6 <= codeEnd) {
                PutByIdMatch(
                    objReg = bundle[pos + 1].toInt() and 0xff,
                    valReg = bundle[pos + 2].toInt() and 0xff,
                    stringId = u16Le(bundle, pos + 4),
                    len = 6,
                )
            } else null
            OP_PUT_BY_ID_LONG, OP_TRY_PUT_BY_ID_LONG -> if (pos + 8 <= codeEnd) {
                val sid = u32Le(bundle, pos + 4).takeIf { it <= Int.MAX_VALUE }?.toInt() ?: return null
                PutByIdMatch(
                    objReg = bundle[pos + 1].toInt() and 0xff,
                    valReg = bundle[pos + 2].toInt() and 0xff,
                    stringId = sid,
                    len = 8,
                )
            } else null
            else -> null
        }
    }

    private fun decodePutNewOwnById(bundle: ByteArray, pos: Int, codeEnd: Int): PutNewOwnMatch? {
        if (pos >= codeEnd) return null
        return when (bundle[pos]) {
            OP_PUT_NEW_OWN_BY_ID_SHORT -> if (pos + 4 <= codeEnd) {
                PutNewOwnMatch(
                    objReg = bundle[pos + 1].toInt() and 0xff,
                    valReg = bundle[pos + 2].toInt() and 0xff,
                    stringId = bundle[pos + 3].toInt() and 0xff,
                    len = 4,
                )
            } else null
            OP_PUT_NEW_OWN_BY_ID, OP_PUT_NEW_OWN_NE_BY_ID -> if (pos + 5 <= codeEnd) {
                PutNewOwnMatch(
                    objReg = bundle[pos + 1].toInt() and 0xff,
                    valReg = bundle[pos + 2].toInt() and 0xff,
                    stringId = u16Le(bundle, pos + 3),
                    len = 5,
                )
            } else null
            OP_PUT_NEW_OWN_BY_ID_LONG, OP_PUT_NEW_OWN_NE_BY_ID_LONG -> if (pos + 7 <= codeEnd) {
                val sid = u32Le(bundle, pos + 3).takeIf { it <= Int.MAX_VALUE }?.toInt() ?: return null
                PutNewOwnMatch(
                    objReg = bundle[pos + 1].toInt() and 0xff,
                    valReg = bundle[pos + 2].toInt() and 0xff,
                    stringId = sid,
                    len = 7,
                )
            } else null
            else -> null
        }
    }

    private fun decodeLoadFromEnvironment(bundle: ByteArray, pos: Int, codeEnd: Int): LoadEnvMatch? {
        if (pos >= codeEnd) return null
        return when (bundle[pos]) {
            OP_LOAD_FROM_ENVIRONMENT -> if (pos + 4 <= codeEnd) {
                LoadEnvMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    envReg = bundle[pos + 2].toInt() and 0xff,
                    len = 4,
                )
            } else null
            0x2f.toByte() -> if (pos + 5 <= codeEnd) {
                LoadEnvMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    envReg = bundle[pos + 2].toInt() and 0xff,
                    len = 5,
                )
            } else null
            else -> null
        }
    }

    private fun decodeCreateClosure(
        bundle: ByteArray,
        pos: Int,
        codeEnd: Int,
        generatorsOnly: Boolean?,
    ): ClosureMatch? {
        if (pos >= codeEnd) return null
        val op = bundle[pos]
        val isGen = when (op) {
            OP_CREATE_CLOSURE, OP_CREATE_CLOSURE_LONG_INDEX -> false
            OP_CREATE_GENERATOR_CLOSURE, OP_CREATE_GENERATOR_CLOSURE_LONG_INDEX,
            OP_CREATE_GENERATOR, OP_CREATE_GENERATOR_LONG_INDEX -> true
            else -> return null
        }
        if (generatorsOnly != null && isGen != generatorsOnly) return null

        val isLong = op == OP_CREATE_CLOSURE_LONG_INDEX ||
            op == OP_CREATE_GENERATOR_CLOSURE_LONG_INDEX ||
            op == OP_CREATE_GENERATOR_LONG_INDEX
        val len = if (isLong) 7 else 5
        if (pos + len > codeEnd) return null
        val fnIdx = if (isLong) {
            u32Le(bundle, pos + 3).takeIf { it <= Int.MAX_VALUE }?.toInt() ?: return null
        } else {
            u16Le(bundle, pos + 3)
        }
        return ClosureMatch(
            dstReg = bundle[pos + 1].toInt() and 0xff,
            envReg = bundle[pos + 2].toInt() and 0xff,
            funcIdx = fnIdx,
            isGenerator = isGen,
            len = len,
        )
    }

    private class CallMatch(
        val dstReg: Int,
        val calleeReg: Int,
        val argRegs: IntArray,
        val len: Int,
    )

    private fun decodeCall(bundle: ByteArray, pos: Int, codeEnd: Int): CallMatch? {
        if (pos >= codeEnd) return null
        return when (bundle[pos]) {
            OP_CALL1 -> if (pos + 4 <= codeEnd) {
                CallMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    calleeReg = bundle[pos + 2].toInt() and 0xff,
                    argRegs = intArrayOf(bundle[pos + 3].toInt() and 0xff),
                    len = 4,
                )
            } else null
            OP_CALL2 -> if (pos + 5 <= codeEnd) {
                CallMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    calleeReg = bundle[pos + 2].toInt() and 0xff,
                    argRegs = intArrayOf(
                        bundle[pos + 3].toInt() and 0xff,
                        bundle[pos + 4].toInt() and 0xff,
                    ),
                    len = 5,
                )
            } else null
            OP_CALL3 -> if (pos + 6 <= codeEnd) {
                CallMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    calleeReg = bundle[pos + 2].toInt() and 0xff,
                    argRegs = intArrayOf(
                        bundle[pos + 3].toInt() and 0xff,
                        bundle[pos + 4].toInt() and 0xff,
                        bundle[pos + 5].toInt() and 0xff,
                    ),
                    len = 6,
                )
            } else null
            0x55.toByte() -> if (pos + 7 <= codeEnd) {
                CallMatch(
                    dstReg = bundle[pos + 1].toInt() and 0xff,
                    calleeReg = bundle[pos + 2].toInt() and 0xff,
                    argRegs = intArrayOf(
                        bundle[pos + 3].toInt() and 0xff,
                        bundle[pos + 4].toInt() and 0xff,
                        bundle[pos + 5].toInt() and 0xff,
                        bundle[pos + 6].toInt() and 0xff,
                    ),
                    len = 7,
                )
            } else null
            else -> null
        }
    }

    private fun decodeJump(bundle: ByteArray, funcBase: Int, pos: Int, codeEnd: Int): JumpMatch? {
        val op = bundle[pos].toInt() and 0xff
        if (op !in 0x8e..0xbf) return null
        val isLong = (op and 1) == 1
        val len = OPCODE_LENGTHS[op]
        if (pos + len > codeEnd) return null
        val rel = if (isLong) i32Le(bundle, pos + 1) else bundle[pos + 1].toInt()
        val relPc = (pos - funcBase) + rel
        return JumpMatch(
            targetRelPc = relPc,
            isConditional = op != 0x8e && op != 0x8f,
            len = len,
        )
    }

    private fun instructionRegAccess(bundle: ByteArray, pos: Int, codeEnd: Int): RegAccess {
        val op = bundle[pos].toInt() and 0xff
        val len = stepInstruction(bundle, pos, codeEnd)
        if (pos + len > codeEnd || op !in OPCODE_LENGTHS.indices) {
            return RegAccess(IntArray(0), IntArray(0), len)
        }
        fun r(off: Int): Int = bundle[pos + off].toInt() and 0xff

        if (op == 0x09) { // MovLong Reg32, Reg32
            return RegAccess(intArrayOf(i32Le(bundle, pos + 1)), intArrayOf(i32Le(bundle, pos + 5)), len)
        }
        if (op in 0x8e..0xbf) {
            return when (op) {
                0x8e, 0x8f -> RegAccess(IntArray(0), IntArray(0), len)
                0x90, 0x92, 0x94, 0x96 -> RegAccess(IntArray(0), intArrayOf(r(2)), len)
                0x91, 0x93, 0x95, 0x97 -> RegAccess(IntArray(0), intArrayOf(r(5)), len)
                else -> if ((op and 1) == 0) {
                    RegAccess(IntArray(0), intArrayOf(r(2), r(3)), len)
                } else {
                    RegAccess(IntArray(0), intArrayOf(r(5), r(6)), len)
                }
            }
        }
        return when (op) {
            0x00, 0x34, 0x35, 0x61, 0x62, 0x63, 0x86, 0x88 -> RegAccess(IntArray(0), IntArray(0), len)
            0x2a, 0x2c -> RegAccess(IntArray(0), intArrayOf(r(1), r(3)), len)
            0x2b, 0x2d -> RegAccess(IntArray(0), intArrayOf(r(1), r(4)), len)
            0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48 ->
                RegAccess(IntArray(0), intArrayOf(r(1), r(2)), len)
            0x46, 0x4a, 0x4b -> RegAccess(IntArray(0), intArrayOf(r(1), r(2), r(3)), len)
            0x4c -> RegAccess(IntArray(0), intArrayOf(r(1), r(2), r(3), r(4)), len)
            0x4d -> RegAccess(intArrayOf(r(1), r(3), r(4)), intArrayOf(r(2), r(3), r(4)), len)
            0x4e -> RegAccess(intArrayOf(r(1), r(4)), intArrayOf(r(2), r(3), r(4), r(5)), len)
            0x5c, 0x5f, 0x85, 0x8d -> RegAccess(IntArray(0), intArrayOf(r(1)), len)
            0x87 -> RegAccess(intArrayOf(r(1), r(2)), IntArray(0), len)
            0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x29, 0x30, 0x31, 0x32,
            0x52, 0x58, 0x59, 0x5a, 0x5b, 0x5d, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
            0x7c, 0x83, 0x84 -> RegAccess(intArrayOf(r(1)), IntArray(0), len)
            0x04, 0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x25, 0x26, 0x2e, 0x2f,
            0x33, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x4f, 0x50, 0x56, 0x57,
            0x5e, 0x60, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x7b, 0x7d,
            0x7e, 0x7f, 0x80, 0x82, 0x89, 0x8a, 0x8b -> RegAccess(intArrayOf(r(1)), intArrayOf(r(2)), len)
            0x53 -> RegAccess(intArrayOf(r(1)), intArrayOf(r(2), r(3), r(4)), len)
            0x54 -> RegAccess(intArrayOf(r(1)), intArrayOf(r(2), r(3), r(4), r(5)), len)
            0x55 -> RegAccess(intArrayOf(r(1)), intArrayOf(r(2), r(3), r(4), r(5), r(6)), len)
            else -> RegAccess(intArrayOf(r(1)), intArrayOf(r(2), r(3)), len)
        }
    }

    private fun emitLoadParam(buf: ByteArrayList, reg: Int, paramIdx: Int) {
        buf.addByte(OP_LOAD_PARAM)
        buf.addByte(reg)
        buf.addByte(paramIdx)
    }

    private fun emitGetById(buf: ByteArrayList, dst: Int, obj: Int, cacheIdx: Int, stringId: Int) {
        when {
            stringId <= 0xff -> {
                buf.addByte(OP_GET_BY_ID_SHORT)
                buf.addByte(dst)
                buf.addByte(obj)
                buf.addByte(cacheIdx)
                buf.addByte(stringId)
            }
            stringId <= 0xffff -> {
                buf.addByte(OP_GET_BY_ID)
                buf.addByte(dst)
                buf.addByte(obj)
                buf.addByte(cacheIdx)
                buf.addU16Le(stringId)
            }
            else -> {
                buf.addByte(OP_GET_BY_ID_LONG)
                buf.addByte(dst)
                buf.addByte(obj)
                buf.addByte(cacheIdx)
                buf.addI32Le(stringId)
            }
        }
    }

    private fun emitLoadConstString(buf: ByteArrayList, dst: Int, stringId: Int) {
        if (stringId <= 0xffff) {
            buf.addByte(OP_LOAD_CONST_STRING)
            buf.addByte(dst)
            buf.addU16Le(stringId)
        } else {
            buf.addByte(OP_LOAD_CONST_STRING_LONG_INDEX)
            buf.addByte(dst)
            buf.addI32Le(stringId)
        }
    }

    private fun emitCreateClosure(buf: ByteArrayList, dst: Int, envReg: Int, funcIdx: Int) {
        if (funcIdx <= 0xffff) {
            buf.addByte(OP_CREATE_CLOSURE)
            buf.addByte(dst)
            buf.addByte(envReg)
            buf.addU16Le(funcIdx)
        } else {
            buf.addByte(OP_CREATE_CLOSURE_LONG_INDEX)
            buf.addByte(dst)
            buf.addByte(envReg)
            buf.addI32Le(funcIdx)
        }
    }

    private class ByteArrayList(initialCapacity: Int) {
        private var data = ByteArray(initialCapacity)
        var size: Int = 0
            private set

        fun addByte(value: Byte) {
            ensureCapacity(1)
            data[size++] = value
        }

        fun addByte(value: Int) = addByte((value and 0xff).toByte())

        fun addU16Le(value: Int) {
            ensureCapacity(2)
            writeU16Le(data, size, value)
            size += 2
        }

        fun addI32Le(value: Int) {
            ensureCapacity(4)
            writeU32Le(data, size, value.toLong() and 0xffffffffL)
            size += 4
        }

        fun addBytes(src: ByteArray, offset: Int, length: Int) {
            ensureCapacity(length)
            System.arraycopy(src, offset, data, size, length)
            size += length
        }

        fun toByteArray(): ByteArray = data.copyOf(size)

        private fun ensureCapacity(extra: Int) {
            val needed = size + extra
            if (needed <= data.size) return
            var next = data.size.coerceAtLeast(32)
            while (next < needed) next = next shl 1
            data = data.copyOf(next)
        }
    }

    private val VIDEO_UPLOAD_REQUIRED_STRINGS = listOf(
        "",
        "?anon_0_",
        "Home",
        "useCameraRoll",
        "getFileSize",
        "MediaTypeOptions",
        "Images",
        "All",
        "mediaTypes",
        "requestMediaLibraryPermissionsAsync",
        "launchImageLibraryAsync",
        "too_large_file_error_message",
        "useCameraRoll - openCameraRoll",
        "MediaTypes",
        "cameraRollImage",
        "type",
        "fileType",
        "uri",
        "onSuccess",
        "reset",
        "current",
        "startLoading",
        "HomeCaptureStage",
        "MEDIA_PROCESSING",
        "onRecordingFinished",
        "generateCroppedVideo",
        "Home-onRecordingFinished",
        "video_recording_error",
        "video",
        "replace",
        "file://",
    )

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
