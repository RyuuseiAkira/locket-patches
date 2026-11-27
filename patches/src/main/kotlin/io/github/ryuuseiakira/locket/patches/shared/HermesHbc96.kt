// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Shared Hermes HBC v96 parser and patcher

package io.github.ryuuseiakira.locket.patches.shared

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Shared pure-Kotlin Hermes bytecode (HBC v96) parser, verifier, and fixed-length patcher for
 * `assets/index.android.bundle`.
 *
 * Attachment: Hermes HBC v96 buffer (`assets/index.android.bundle`) parsed by header, function
 * table, string table, and trailing SHA-1 integrity footer.
 * Mechanism: Validates magic, version 96, exact `fileLength`, and trailing SHA-1 digest, maps
 * needed string table indices and function headers (`SmallFuncHeader` and `LargeFuncHeader`),
 * applies length-preserving in-place bytecode rewrites, and recomputes the trailing SHA-1 footer.
 * Constraint: Fixed-length in-place writes preserve all function/table offsets; every rewrite rule
 * must resolve a single unambiguous site (matching an explicit expected count) and pass bounds and
 * prologue/sequence verification.
 */
object HermesHbc96 {
    const val BUNDLE_PATH: String = "assets/index.android.bundle"

    const val HBC_MAGIC: Long = 0x1f1903c103bc1fc6L
    const val HBC_VERSION: Int = 96
    const val HEADER_SIZE: Int = 128
    const val SHA1_SIZE: Int = 20

    const val OP_UNREACHABLE: Byte = 0x00
    const val OP_NEW_OBJECT: Byte = 0x03
    const val OP_GET_BY_ID: Byte = 0x37
    const val OP_PUT_BY_ID: Byte = 0x38
    const val OP_PUT_NEW_OWN_BY_ID: Byte = 0x40
    const val OP_PUT_OWN_BY_ID: Byte = 0x41
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
    private const val OFF_DEBUG_INFO_OFFSET: Int = 0x68

    private const val MIN_REMOTE_CONFIG_CALL2_LEN: Int = 17

    /** Describes an in-place HBC v96 bytecode mutation applied atomically within one bundle pass. */
    sealed interface Mutation {
        val label: String

        /**
         * Matches `GetById(rFn, rObj, getterName); LoadConstString[LongIndex](rArg, configKey);
         * Call2(rDst, rFn, rObj, rArg); Ret(rDst)` inside the unique named helper function and
         * replaces the 5-byte `Call2` instruction with `returnOpcode rDst; Ret rDst; Unreachable`.
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
         * Rewrites `HomeCamera`'s pinch-zoom worklet factory (`__initData.code`) and fallback JS
         * closure to multiplicative power scaling clamped to `[minZoom, maxZoom]`.
         */
        data class ImprovePinchZoomWorklet(
            val factoryFunctionName: String,
            val workletFunctionName: String,
            val exponent: Double = 1.8,
            val minScaleClamp: Double = 0.01,
        ) : Mutation {
            override val label: String
                get() = "ImprovePinchZoomWorklet($workletFunctionName)"
        }

        /**
         * Upgrades `Home`, `CameraOverlayZoomButton`, its `onPress` callback, and
         * `getNextZoomValue` to cycle `0.5x -> 1x -> 3x` when a back telephoto camera is present.
         */
        data class EnableTelephotoZoomToggle(
            val zoomThreshold: Double = 3.0,
            val zoomTolerance: Double = 0.05,
        ) : Mutation {
            override val label: String
                get() = "EnableTelephotoZoomToggle(${zoomThreshold}x)"
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

    internal data class FunctionMeta(
        val index: Int,
        val nameId: Int,
        var codeOffset: Int,
        var codeSize: Int,
        var paramCount: Int,
        var infoOffset: Int,
        var frameSize: Int,
        var environmentSize: Int,
        var highestReadCacheIndex: Int,
        var highestWriteCacheIndex: Int,
        var flags: Int,
        var overflowed: Boolean,
        var largeHeaderOffset: Int,
    ) {
        val hasExceptionHandler: Boolean
            get() = (flags and 0x08) != 0
    }

    internal class PatchContext(
        val baseBundle: ByteArray,
        val stringIds: Map<String, Int>,
        val allFunctions: List<FunctionMeta>,
        val functionsByNameId: Map<Int, List<FunctionMeta>>,
        val tailBaseOffset: Int,
    ) {
        private val relocatedTail = ByteArrayOutputStream()

        fun hasRelocatedTail(): Boolean = relocatedTail.size() > 0

        fun relocatedTailBytes(): ByteArray = relocatedTail.toByteArray()

        fun functionCode(fn: FunctionMeta): ByteArray {
            return if (fn.codeOffset + fn.codeSize <= tailBaseOffset) {
                baseBundle.copyOfRange(fn.codeOffset, fn.codeOffset + fn.codeSize)
            } else {
                val relOff = fn.codeOffset - tailBaseOffset
                val tail = relocatedTail.toByteArray()
                require(relOff >= 0 && relOff + fn.codeSize <= tail.size) {
                    "Relocated function #${fn.index} (${relOff} + ${fn.codeSize}) exceeds tail bounds (${tail.size})."
                }
                tail.copyOfRange(relOff, relOff + fn.codeSize)
            }
        }

        fun functionContainsAllStrings(fn: FunctionMeta, requiredStrings: List<String>): Boolean {
            if (requiredStrings.isEmpty()) return true
            val remaining = LinkedHashSet<Int>(requiredStrings.size)
            for (s in requiredStrings) remaining.add(stringIds.getValue(s))
            val buf: ByteArray
            val startOff: Int
            if (fn.codeOffset + fn.codeSize <= tailBaseOffset) {
                buf = baseBundle
                startOff = fn.codeOffset
            } else {
                buf = functionCode(fn)
                startOff = 0
            }
            val ins = HermesHbc96Asm.decodeFunction(buf, startOff, startOff + fn.codeSize)
            for (item in ins) {
                val off = startOff + item.offset
                val id = HermesHbc96Asm.readGetById(buf, off)?.stringId
                    ?: HermesHbc96Asm.readPutById(buf, off)?.stringId
                    ?: HermesHbc96Asm.readPutNewOwnById(buf, off)?.stringId
                    ?: HermesHbc96Asm.readLoadConstString(buf, off)?.second
                if (id != null) {
                    remaining.remove(id)
                    if (remaining.isEmpty()) return true
                }
            }
            return remaining.isEmpty()
        }

        fun writeFunctionCode(
            fn: FunctionMeta,
            newCode: ByteArray,
            newParamCount: Int = fn.paramCount,
            newFrameSize: Int = fn.frameSize,
            newEnvironmentSize: Int = fn.environmentSize,
            newReadCacheIndex: Int = fn.highestReadCacheIndex,
            newWriteCacheIndex: Int = fn.highestWriteCacheIndex,
        ): Int {
            fn.paramCount = newParamCount
            fn.frameSize = newFrameSize
            fn.environmentSize = newEnvironmentSize
            fn.highestReadCacheIndex = newReadCacheIndex
            fn.highestWriteCacheIndex = newWriteCacheIndex

            if (newCode.size <= fn.codeSize && fn.codeOffset + fn.codeSize <= tailBaseOffset) {
                System.arraycopy(newCode, 0, baseBundle, fn.codeOffset, newCode.size)
                for (i in newCode.size until fn.codeSize) {
                    baseBundle[fn.codeOffset + i] = OP_UNREACHABLE
                }
            } else {
                val relocatedOff = tailBaseOffset + relocatedTail.size()
                relocatedTail.write(newCode)
                fn.codeOffset = relocatedOff
                fn.codeSize = newCode.size
            }

            writeFunctionHeader(baseBundle, relocatedTail, tailBaseOffset, fn)
            return fn.codeOffset
        }
    }

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
        val rawDebugOffset = readCount(bundle, OFF_DEBUG_INFO_OFFSET, contentEnd, "debugInfoOffset")

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
        val hasDebugSection = rawDebugOffset > 0
        val tailBaseOffset = if (hasDebugSection) {
            require(rawDebugOffset.toLong() >= strStorageEnd && rawDebugOffset <= contentEnd) {
                "Hermes header debugInfoOffset ($rawDebugOffset) out of valid range [$strStorageEnd, $contentEnd]."
            }
            rawDebugOffset
        } else {
            contentEnd
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

        val (allFunctions, functionsByNameId) = parseAllFunctions(
            bundle = bundle,
            functionCount = functionCount,
            contentEnd = contentEnd,
            wantedNameIds = buildSet {
                for (mutation in mutations) {
                    when (mutation) {
                        is Mutation.RemoteConfigReturnConst -> add(stringIds.getValue(mutation.functionName))
                        is Mutation.FunctionEarlyReturn -> add(stringIds.getValue(mutation.functionName))
                        is Mutation.GeneratorEarlyReturn -> add(stringIds.getValue(mutation.functionName))
                        is Mutation.ImprovePinchZoomWorklet -> {
                            add(stringIds.getValue(mutation.factoryFunctionName))
                            add(stringIds.getValue(mutation.workletFunctionName))
                        }
                        is Mutation.EnableTelephotoZoomToggle -> {
                            add(stringIds.getValue("Home"))
                            add(stringIds.getValue("getNextZoomValue"))
                        }
                    }
                }
            },
        )

        val baseBundle = bundle.copyOfRange(0, tailBaseOffset)
        val ctx = PatchContext(
            baseBundle = baseBundle,
            stringIds = stringIds,
            allFunctions = allFunctions,
            functionsByNameId = functionsByNameId,
            tailBaseOffset = tailBaseOffset,
        )

        val appliedSites = ArrayList<AppliedSite>(mutations.size)
        for (mutation in mutations) {
            val site = when (mutation) {
                is Mutation.RemoteConfigReturnConst -> applyRemoteConfigReturnConst(
                    bundle = baseBundle,
                    stringIds = stringIds,
                    functionsByNameId = functionsByNameId,
                    mutation = mutation,
                )
                is Mutation.FunctionEarlyReturn -> applyFunctionEarlyReturn(
                    bundle = baseBundle,
                    stringIds = stringIds,
                    functionsByNameId = functionsByNameId,
                    mutation = mutation,
                )
                is Mutation.GeneratorEarlyReturn -> applyGeneratorEarlyReturn(
                    bundle = baseBundle,
                    stringIds = stringIds,
                    functionsByNameId = functionsByNameId,
                    mutation = mutation,
                )
                is Mutation.ImprovePinchZoomWorklet ->
                    HermesHbc96CameraMutations.applyImprovePinchZoomWorklet(ctx, mutation)
                is Mutation.EnableTelephotoZoomToggle ->
                    HermesHbc96CameraMutations.applyEnableTelephotoZoomToggle(ctx, mutation)
            }
            appliedSites.add(site)
        }

        val finalBundle = if (!ctx.hasRelocatedTail()) {
            val out = ByteArray(bundle.size)
            System.arraycopy(baseBundle, 0, out, 0, tailBaseOffset)
            if (hasDebugSection && tailBaseOffset < contentEnd) {
                System.arraycopy(bundle, tailBaseOffset, out, tailBaseOffset, contentEnd - tailBaseOffset)
            }
            out
        } else {
            val relocatedTail = ctx.relocatedTailBytes()
            val preDebugSize = tailBaseOffset + relocatedTail.size
            val alignedDebugOff = align4(preDebugSize.toLong()).toInt()
            val debugLen = if (hasDebugSection) contentEnd - tailBaseOffset else 0
            val newContentEnd = alignedDebugOff + debugLen
            val out = ByteArray(newContentEnd + SHA1_SIZE)
            System.arraycopy(baseBundle, 0, out, 0, tailBaseOffset)
            System.arraycopy(relocatedTail, 0, out, tailBaseOffset, relocatedTail.size)
            if (hasDebugSection && debugLen > 0) {
                System.arraycopy(bundle, tailBaseOffset, out, alignedDebugOff, debugLen)
                writeI32Le(out, OFF_DEBUG_INFO_OFFSET, alignedDebugOff)
            }
            writeI32Le(out, OFF_FILE_LENGTH, out.size)
            out
        }

        val finalContentEnd = finalBundle.size - SHA1_SIZE
        val newDigest = sha1(finalBundle, finalContentEnd)
        System.arraycopy(newDigest, 0, finalBundle, finalContentEnd, SHA1_SIZE)

        return BatchPatchResult(bytes = finalBundle, appliedSites = appliedSites)
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
                is Mutation.ImprovePinchZoomWorklet -> {
                    out.add(mutation.factoryFunctionName)
                    out.add(mutation.workletFunctionName)
                    out.addAll(
                        listOf(
                            "__initData",
                            "code",
                            "indexOf",
                            "__closure",
                            "slice",
                            ".",
                            "(",
                            ")",
                            ",",
                            "*",
                            ";",
                            "}",
                            "scale",
                            "Math",
                            "pow",
                            "min",
                            "max",
                            "value",
                            "set",
                            "zoom",
                            "minZoom",
                            "pinchStartZoom",
                            "maxZoom",
                            "event",
                        ),
                    )
                }
                is Mutation.EnableTelephotoZoomToggle -> {
                    out.addAll(
                        listOf(
                            "Home",
                            "getNextZoomValue",
                            "device",
                            "zoomProps",
                            "minZoom",
                            "neutralZoom",
                            "zoom",
                            "back",
                            "backFacing",
                            "camera_theme",
                            "lensSwitch",
                            "maxZoom",
                            "telephone",
                            "slice",
                            "photo",
                            "type",
                            "physicalDevices",
                            "Array",
                            "isArray",
                            "length",
                            "CameraOverlayButton",
                            "useDeviceOrientationRotationStyle",
                            "overlayZoomButtonProps",
                        ),
                    )
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

    private fun parseAllFunctions(
        bundle: ByteArray,
        functionCount: Int,
        contentEnd: Int,
        wantedNameIds: Set<Int>,
    ): Pair<List<FunctionMeta>, Map<Int, List<FunctionMeta>>> {
        val grouped = LinkedHashMap<Int, MutableList<FunctionMeta>>()
        for (id in wantedNameIds) {
            grouped[id] = ArrayList(2)
        }
        val all = ArrayList<FunctionMeta>(functionCount)

        for (funcIdx in 0 until functionCount) {
            val hOff = HEADER_SIZE + funcIdx * SMALL_FUNC_HEADER_SIZE
            val w0 = i32Le(bundle, hOff)
            val w1 = i32Le(bundle, hOff + 4)
            val w2 = i32Le(bundle, hOff + 8)
            val w3 = i32Le(bundle, hOff + 12)
            val flags = (w3 ushr 24) and 0xff
            val overflowed = ((flags ushr 5) and 1) != 0

            val meta: FunctionMeta
            if (!overflowed) {
                val codeOffset = w0 and 0x1ffffff
                val codeSize = w1 and 0x7fff
                val nameIdx = (w1 ushr 15) and 0x1ffff
                require(codeOffset >= HEADER_SIZE && codeOffset + codeSize <= contentEnd) {
                    "Bytecode range ($codeOffset + $codeSize) for function #$funcIdx out of bounds."
                }
                meta = FunctionMeta(
                    index = funcIdx,
                    nameId = nameIdx,
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
                    largeHeaderOffset = -1,
                )
            } else {
                val largeOffset = (((w2 and 0xffff).toLong() shl 16) or (w0 and 0xffff).toLong())
                require(largeOffset >= HEADER_SIZE && largeOffset + LARGE_FUNC_HEADER_SIZE <= contentEnd) {
                    "LargeFuncHeader offset $largeOffset for function #$funcIdx out of bounds."
                }
                val lo = largeOffset.toInt()
                val codeOffset = u32Le(bundle, lo)
                val paramCount = u32Le(bundle, lo + 4)
                val largeSize = u32Le(bundle, lo + 8)
                val largeName = u32Le(bundle, lo + 12)
                val infoOffset = u32Le(bundle, lo + 16)
                val frameSize = u32Le(bundle, lo + 20)
                val envSize = u32Le(bundle, lo + 24)
                require(
                    codeOffset <= Int.MAX_VALUE &&
                        paramCount <= Int.MAX_VALUE &&
                        largeSize <= Int.MAX_VALUE &&
                        largeName <= Int.MAX_VALUE &&
                        infoOffset <= Int.MAX_VALUE &&
                        frameSize <= Int.MAX_VALUE &&
                        envSize <= Int.MAX_VALUE &&
                        codeOffset >= HEADER_SIZE &&
                        codeOffset + largeSize <= contentEnd
                ) {
                    "LargeFuncHeader fields out of range for function #$funcIdx."
                }
                meta = FunctionMeta(
                    index = funcIdx,
                    nameId = largeName.toInt(),
                    codeOffset = codeOffset.toInt(),
                    codeSize = largeSize.toInt(),
                    paramCount = paramCount.toInt(),
                    infoOffset = infoOffset.toInt(),
                    frameSize = frameSize.toInt(),
                    environmentSize = envSize.toInt(),
                    highestReadCacheIndex = bundle[lo + 28].toInt() and 0xff,
                    highestWriteCacheIndex = bundle[lo + 29].toInt() and 0xff,
                    flags = bundle[lo + 30].toInt() and 0xff,
                    overflowed = true,
                    largeHeaderOffset = lo,
                )
            }

            all.add(meta)
            grouped[meta.nameId]?.add(meta)
        }

        return all to grouped
    }

    private fun writeFunctionHeader(
        baseBundle: ByteArray,
        relocatedTail: ByteArrayOutputStream,
        tailBaseOffset: Int,
        fn: FunctionMeta,
    ) {
        val fitsSmall = !fn.overflowed &&
            fn.codeOffset in 0 until (1 shl 25) &&
            fn.paramCount in 0 until (1 shl 7) &&
            fn.codeSize in 0 until (1 shl 15) &&
            fn.nameId in 0 until (1 shl 17) &&
            fn.infoOffset in 0 until (1 shl 25) &&
            fn.frameSize in 0 until (1 shl 7) &&
            fn.environmentSize in 0 until (1 shl 8) &&
            fn.highestReadCacheIndex in 0 until (1 shl 8) &&
            fn.highestWriteCacheIndex in 0 until (1 shl 8)

        val hOff = HEADER_SIZE + fn.index * SMALL_FUNC_HEADER_SIZE
        if (fitsSmall) {
            val w0 = (fn.codeOffset and 0x1ffffff) or ((fn.paramCount and 0x7f) shl 25)
            val w1 = (fn.codeSize and 0x7fff) or ((fn.nameId and 0x1ffff) shl 15)
            val w2 = (fn.infoOffset and 0x1ffffff) or ((fn.frameSize and 0x7f) shl 25)
            val w3 = (fn.environmentSize and 0xff) or
                ((fn.highestReadCacheIndex and 0xff) shl 8) or
                ((fn.highestWriteCacheIndex and 0xff) shl 16) or
                ((fn.flags and 0xdf) shl 24)
            writeI32Le(baseBundle, hOff, w0)
            writeI32Le(baseBundle, hOff + 4, w1)
            writeI32Le(baseBundle, hOff + 8, w2)
            writeI32Le(baseBundle, hOff + 12, w3)
            return
        }

        if (fn.overflowed && fn.largeHeaderOffset in HEADER_SIZE..(tailBaseOffset - LARGE_FUNC_HEADER_SIZE)) {
            val lo = fn.largeHeaderOffset
            writeI32Le(baseBundle, lo, fn.codeOffset)
            writeI32Le(baseBundle, lo + 4, fn.paramCount)
            writeI32Le(baseBundle, lo + 8, fn.codeSize)
            writeI32Le(baseBundle, lo + 12, fn.nameId)
            writeI32Le(baseBundle, lo + 16, fn.infoOffset)
            writeI32Le(baseBundle, lo + 20, fn.frameSize)
            writeI32Le(baseBundle, lo + 24, fn.environmentSize)
            baseBundle[lo + 28] = fn.highestReadCacheIndex.toByte()
            baseBundle[lo + 29] = fn.highestWriteCacheIndex.toByte()
            baseBundle[lo + 30] = (fn.flags and 0xdf).toByte()
            return
        }

        while ((tailBaseOffset + relocatedTail.size()) and 3 != 0) {
            relocatedTail.write(0)
        }
        val newLargeOff = tailBaseOffset + relocatedTail.size()
        val large = ByteArray(LARGE_FUNC_HEADER_SIZE)
        writeI32Le(large, 0, fn.codeOffset)
        writeI32Le(large, 4, fn.paramCount)
        writeI32Le(large, 8, fn.codeSize)
        writeI32Le(large, 12, fn.nameId)
        writeI32Le(large, 16, fn.infoOffset)
        writeI32Le(large, 20, fn.frameSize)
        writeI32Le(large, 24, fn.environmentSize)
        large[28] = fn.highestReadCacheIndex.toByte()
        large[29] = fn.highestWriteCacheIndex.toByte()
        large[30] = (fn.flags and 0xdf).toByte()
        relocatedTail.write(large)

        writeI32Le(baseBundle, hOff, newLargeOff and 0xffff)
        writeI32Le(baseBundle, hOff + 4, 0)
        writeI32Le(baseBundle, hOff + 8, (newLargeOff ushr 16) and 0xffff)
        writeI32Le(baseBundle, hOff + 12, (fn.flags or 0x20) shl 24)
        fn.overflowed = true
        fn.largeHeaderOffset = newLargeOff
    }

    private fun applyRemoteConfigReturnConst(
        bundle: ByteArray,
        stringIds: Map<String, Int>,
        functionsByNameId: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.RemoteConfigReturnConst,
    ): AppliedSite {
        val fnNameId = stringIds.getValue(mutation.functionName)
        val getterId = stringIds.getValue(mutation.getterMethodName)
        val keyId = stringIds.getValue(mutation.configKey)

        val candidates = functionsByNameId.getValue(fnNameId)
        require(candidates.size == 1) {
            "Expected 1 '${mutation.functionName}' function, found ${candidates.size}."
        }
        val fn = candidates[0]

        var matchedCallOffset = -1
        var matchedReturnRegister = -1
        var matchCount = 0

        if (fn.codeSize >= MIN_REMOTE_CONFIG_CALL2_LEN) {
            val codeEnd = fn.codeOffset + fn.codeSize
            val lastStart = codeEnd - MIN_REMOTE_CONFIG_CALL2_LEN
            var offset = fn.codeOffset

            while (offset <= lastStart) {
                if (bundle[offset] != OP_GET_BY_ID || u16Le(bundle, offset + 4) != getterId) {
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
                        if (u16Le(bundle, next + 2) != keyId) {
                            offset++
                            continue
                        }
                        rArg = bundle[next + 1]
                        callOffset = next + 4
                    }
                    OP_LOAD_CONST_STRING_LONG_INDEX -> {
                        if (next + 6 + 7 > codeEnd || u32Le(bundle, next + 2) != keyId.toLong()) {
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
                        matchCount++
                        matchedCallOffset = callOffset
                        matchedReturnRegister = rDst.toInt() and 0xff
                        offset = callOffset + 7
                        continue
                    }
                }

                offset++
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
        functionsByNameId: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.FunctionEarlyReturn,
    ): AppliedSite {
        require(mutation.replacement.isNotEmpty()) {
            "Replacement bytes for ${mutation.label} must not be empty."
        }
        val fnNameId = stringIds.getValue(mutation.functionName)
        val reqIds = mutation.requiredStrings.map(stringIds::getValue)
        val matching = functionsByNameId.getValue(fnNameId).filter { fn ->
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
        functionsByNameId: Map<Int, List<FunctionMeta>>,
        mutation: Mutation.GeneratorEarlyReturn,
    ): AppliedSite {
        val fnNameId = stringIds.getValue(mutation.functionName)
        val reqIds = mutation.requiredStrings.map(stringIds::getValue)
        val matching = functionsByNameId.getValue(fnNameId).filter { fn ->
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

    private fun containsAllStringRefs(
        bundle: ByteArray,
        codeOffset: Int,
        codeSize: Int,
        requiredIds: List<Int>,
    ): Boolean {
        if (requiredIds.isEmpty()) return true
        val codeEnd = codeOffset + codeSize
        val remaining = LinkedHashSet(requiredIds)

        // Scans 2-byte and 4-byte string/identifier reference slots aligned at opcode boundaries or
        // arbitrary offsets within [codeOffset, codeEnd) for matching property-id and const-string
        // instruction shapes (GetById, PutById, PutNewOwnById, PutOwnById, LoadConstString).
        var pos = codeOffset
        while (pos < codeEnd && remaining.isNotEmpty()) {
            val op = bundle[pos]
            when {
                (op == OP_GET_BY_ID || op == OP_PUT_BY_ID || op == OP_PUT_NEW_OWN_BY_ID || op == OP_PUT_OWN_BY_ID) &&
                    pos + 6 <= codeEnd -> {
                    remaining.remove(u16Le(bundle, pos + 4))
                }
                op == OP_LOAD_CONST_STRING && pos + 4 <= codeEnd -> {
                    remaining.remove(u16Le(bundle, pos + 2))
                }
                op == OP_LOAD_CONST_STRING_LONG_INDEX && pos + 6 <= codeEnd -> {
                    val longId = u32Le(bundle, pos + 2)
                    if (longId <= Int.MAX_VALUE) {
                        remaining.remove(longId.toInt())
                    }
                }
            }
            pos++
        }
        return remaining.isEmpty()
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

    internal fun readU16Le(bytes: ByteArray, offset: Int): Int = u16Le(bytes, offset)

    internal fun readI32Le(bytes: ByteArray, offset: Int): Int = i32Le(bytes, offset)

    internal fun readU32Le(bytes: ByteArray, offset: Int): Long = u32Le(bytes, offset)

    internal fun writeI32Le(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xff).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xff).toByte()
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
