// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96Asm.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / HBC v96 instruction decoder and relocatable assembler

package io.github.ryuuseiakira.locket.patches.shared

import java.io.ByteArrayOutputStream

/**
 * Compact HBC v96 instruction length table, register/cache scanner, and relative-branch
 * assembler used when rewriting or relocating bytecode functions.
 */
internal object HermesHbc96Asm {
    const val OP_MOV: Byte = 0x08
    const val OP_MOV_LONG: Byte = 0x09
    const val OP_STRICT_EQ: Byte = 0x0f
    const val OP_LESS: Byte = 0x12
    const val OP_ADD: Byte = 0x16
    const val OP_MUL: Byte = 0x18
    const val OP_SUB: Byte = 0x1d
    const val OP_GET_ENVIRONMENT: Byte = 0x29
    const val OP_STORE_TO_ENVIRONMENT: Byte = 0x2a
    const val OP_STORE_TO_ENVIRONMENT_L: Byte = 0x2b
    const val OP_LOAD_FROM_ENVIRONMENT: Byte = 0x2e
    const val OP_LOAD_FROM_ENVIRONMENT_L: Byte = 0x2f
    const val OP_GET_GLOBAL_OBJECT: Byte = 0x30
    const val OP_CREATE_ENVIRONMENT: Byte = 0x32
    const val OP_GET_BY_ID_SHORT: Byte = 0x36
    const val OP_GET_BY_ID: Byte = 0x37
    const val OP_GET_BY_ID_LONG: Byte = 0x38
    const val OP_TRY_GET_BY_ID: Byte = 0x39
    const val OP_TRY_GET_BY_ID_LONG: Byte = 0x3a
    const val OP_PUT_NEW_OWN_BY_ID_SHORT: Byte = 0x3f
    const val OP_PUT_NEW_OWN_BY_ID: Byte = 0x40
    const val OP_PUT_NEW_OWN_BY_ID_LONG: Byte = 0x41
    const val OP_PUT_BY_ID: Byte = 0x3b
    const val OP_PUT_BY_ID_LONG: Byte = 0x3c
    const val OP_GET_BY_VAL: Byte = 0x49
    const val OP_PUT_BY_VAL: Byte = 0x4a
    const val OP_CALL: Byte = 0x4f
    const val OP_CONSTRUCT: Byte = 0x50
    const val OP_CALL1: Byte = 0x51
    const val OP_CALL_DIRECT: Byte = 0x52
    const val OP_CALL2: Byte = 0x53
    const val OP_CALL3: Byte = 0x54
    const val OP_CALL4: Byte = 0x55
    const val OP_CALL_LONG: Byte = 0x56
    const val OP_CONSTRUCT_LONG: Byte = 0x57
    const val OP_CALL_DIRECT_LONG_INDEX: Byte = 0x58
    const val OP_CALL_BUILTIN: Byte = 0x59
    const val OP_CALL_BUILTIN_LONG: Byte = 0x5a
    const val OP_CREATE_CLOSURE: Byte = 0x64
    const val OP_CREATE_CLOSURE_LONG_INDEX: Byte = 0x65
    const val OP_LOAD_PARAM: Byte = 0x6c
    const val OP_LOAD_CONST_UINT8: Byte = 0x6e
    const val OP_LOAD_CONST_DOUBLE: Byte = 0x70
    const val OP_JMP: Byte = 0x8e.toByte()
    const val OP_JMP_LONG: Byte = 0x8f.toByte()
    const val OP_JMP_FALSE_LONG: Byte = 0x93.toByte()
    const val OP_J_LESS_LONG: Byte = 0x99.toByte()
    const val OP_J_NOT_LESS_LONG: Byte = 0x9b.toByte()
    const val OP_J_LESS_EQUAL_LONG: Byte = 0xa1.toByte()
    const val OP_J_STRICT_EQUAL_LONG: Byte = 0xbd.toByte()
    const val OP_J_STRICT_NOT_EQUAL_LONG: Byte = 0xbf.toByte()

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

    private val REG8_MASKS = intArrayOf(
        0, 1, 1, 1, 3, 1, 1, 1, 3, 0, 3, 3, 3, 3, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 3, 3, 7, 7, 1, 5, 9, 5, 9, 3, 3,
        1, 1, 1, 3, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 7, 3, 3, 7, 7, 7, 15, 15, 31, 3,
        3, 7, 1, 15, 31, 63, 3, 3, 1, 1, 1, 1, 1, 1, 3, 1,
        3, 0, 0, 0, 3, 3, 3, 3, 3, 3, 7, 7, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 3, 3,
        3, 7, 3, 1, 1, 1, 0, 3, 0, 3, 3, 3, 7, 1, 0, 0,
        2, 16, 2, 16, 2, 16, 0, 0, 6, 48, 6, 48, 6, 48, 6, 48,
        6, 48, 6, 48, 6, 48, 6, 48, 6, 48, 6, 48, 6, 48, 6, 48,
        6, 48, 6, 48, 6, 48, 6, 48, 6, 48, 6, 48, 6, 48, 6, 48,
    )

    data class DecodedInstruction(
        val offset: Int,
        val length: Int,
        val opcode: Byte,
    )

    data class IdAccess(
        val regDst: Int,
        val regObj: Int,
        val cacheIndex: Int,
        val stringId: Int,
        val length: Int,
    )

    data class PutNewOwnIdAccess(
        val regObj: Int,
        val regVal: Int,
        val stringId: Int,
        val length: Int,
    )

    data class ClosureCreate(
        val regDst: Int,
        val regEnv: Int,
        val functionId: Int,
        val length: Int,
    )

    data class EnvStore(
        val regEnv: Int,
        val envSlot: Int,
        val regVal: Int,
        val length: Int,
    )

    fun instructionLength(opcode: Byte): Int {
        val id = opcode.toInt() and 0xff
        require(id < OPCODE_LENGTHS.size) { "Unknown HBC v96 opcode 0x${id.toString(16)}." }
        return OPCODE_LENGTHS[id]
    }

    fun decodeFunction(code: ByteArray, start: Int = 0, end: Int = code.size): List<DecodedInstruction> {
        val out = ArrayList<DecodedInstruction>((end - start) / 3 + 4)
        var pos = start
        while (pos < end) {
            val op = code[pos]
            val len = instructionLength(op)
            require(pos + len <= end) {
                "Truncated HBC v96 opcode 0x${(op.toInt() and 0xff).toString(16)} at offset $pos ($end)."
            }
            out.add(DecodedInstruction(offset = pos - start, length = len, opcode = op))
            pos += len
        }
        return out
    }

    fun scanMaxRegisterAndReadCache(
        code: ByteArray,
        instructions: List<DecodedInstruction>,
        baseOffset: Int = 0,
    ): Pair<Int, Int> {
        var maxReg = -1
        var maxReadCache = 0
        for (ins in instructions) {
            val pos = baseOffset + ins.offset
            val opId = ins.opcode.toInt() and 0xff
            if (ins.opcode == OP_MOV_LONG) {
                val r1 = HermesHbc96.readI32Le(code, pos + 1)
                val r2 = HermesHbc96.readI32Le(code, pos + 5)
                if (r1 > maxReg) maxReg = r1
                if (r2 > maxReg) maxReg = r2
            } else {
                var mask = REG8_MASKS[opId]
                var bit = 0
                while (mask != 0) {
                    if ((mask and 1) != 0) {
                        val reg = code[pos + 1 + bit].toInt() and 0xff
                        if (reg > maxReg) maxReg = reg
                    }
                    mask = mask ushr 1
                    bit++
                }
            }
            if (opId in 0x36..0x3a) {
                val cacheIdx = code[pos + 3].toInt() and 0xff
                if (cacheIdx > maxReadCache) maxReadCache = cacheIdx
            }
        }
        return maxReg to maxReadCache
    }

    data class CallFrameSummary(
        val maxOutgoingSlots: Int,
        val hasStackTopRelativeCall: Boolean,
    )

    /**
     * Computes the maximum caller-top frame slots reserved by outgoing call instructions (`6` Hermes
     * metadata slots + explicit `argCount` including `this`) and whether any instruction addresses
     * stack-top-relative slots (`Call`, `Construct`, `CallDirect`, `CallBuiltin`, or their
     * `*Long` variants) whose indices shift if `frameSize` grows.
     */
    fun scanCallFrameRequirements(
        code: ByteArray,
        instructions: List<DecodedInstruction>,
        baseOffset: Int = 0,
    ): CallFrameSummary {
        var maxOutgoingSlots = 0
        var hasStackTopRelativeCall = false
        for (ins in instructions) {
            val pos = baseOffset + ins.offset
            val slots = when (ins.opcode) {
                OP_CALL1 -> 7
                OP_CALL2 -> 8
                OP_CALL3 -> 9
                OP_CALL4 -> 10
                OP_CALL, OP_CONSTRUCT, OP_CALL_BUILTIN -> {
                    hasStackTopRelativeCall = true
                    6 + (code[pos + 3].toInt() and 0xff)
                }
                OP_CALL_DIRECT, OP_CALL_DIRECT_LONG_INDEX -> {
                    hasStackTopRelativeCall = true
                    6 + (code[pos + 2].toInt() and 0xff)
                }
                OP_CALL_LONG, OP_CONSTRUCT_LONG, OP_CALL_BUILTIN_LONG -> {
                    hasStackTopRelativeCall = true
                    val argc = HermesHbc96.readI32Le(code, pos + 3)
                    require(argc >= 0) { "Negative long call argCount ($argc) at +$pos." }
                    6 + argc
                }
                else -> 0
            }
            if (slots > maxOutgoingSlots) maxOutgoingSlots = slots
        }
        return CallFrameSummary(maxOutgoingSlots, hasStackTopRelativeCall)
    }

    fun readGetById(bytes: ByteArray, pos: Int): IdAccess? {
        return when (bytes[pos]) {
            OP_GET_BY_ID_SHORT -> IdAccess(
                regDst = bytes[pos + 1].toInt() and 0xff,
                regObj = bytes[pos + 2].toInt() and 0xff,
                cacheIndex = bytes[pos + 3].toInt() and 0xff,
                stringId = bytes[pos + 4].toInt() and 0xff,
                length = 5,
            )
            OP_GET_BY_ID, OP_TRY_GET_BY_ID -> IdAccess(
                regDst = bytes[pos + 1].toInt() and 0xff,
                regObj = bytes[pos + 2].toInt() and 0xff,
                cacheIndex = bytes[pos + 3].toInt() and 0xff,
                stringId = HermesHbc96.readU16Le(bytes, pos + 4),
                length = 6,
            )
            OP_GET_BY_ID_LONG, OP_TRY_GET_BY_ID_LONG -> {
                val id = HermesHbc96.readU32Le(bytes, pos + 4)
                if (id > Int.MAX_VALUE) null else IdAccess(
                    regDst = bytes[pos + 1].toInt() and 0xff,
                    regObj = bytes[pos + 2].toInt() and 0xff,
                    cacheIndex = bytes[pos + 3].toInt() and 0xff,
                    stringId = id.toInt(),
                    length = 8,
                )
            }
            else -> null
        }
    }

    fun readPutById(bytes: ByteArray, pos: Int): IdAccess? {
        return when (bytes[pos]) {
            OP_PUT_BY_ID -> IdAccess(
                regDst = bytes[pos + 1].toInt() and 0xff, // target object
                regObj = bytes[pos + 2].toInt() and 0xff, // value
                cacheIndex = bytes[pos + 3].toInt() and 0xff,
                stringId = HermesHbc96.readU16Le(bytes, pos + 4),
                length = 6,
            )
            OP_PUT_BY_ID_LONG -> {
                val id = HermesHbc96.readU32Le(bytes, pos + 4)
                if (id > Int.MAX_VALUE) null else IdAccess(
                    regDst = bytes[pos + 1].toInt() and 0xff,
                    regObj = bytes[pos + 2].toInt() and 0xff,
                    cacheIndex = bytes[pos + 3].toInt() and 0xff,
                    stringId = id.toInt(),
                    length = 8,
                )
            }
            else -> null
        }
    }

    fun readPutNewOwnById(bytes: ByteArray, pos: Int): PutNewOwnIdAccess? {
        return when (bytes[pos]) {
            OP_PUT_NEW_OWN_BY_ID_SHORT -> PutNewOwnIdAccess(
                regObj = bytes[pos + 1].toInt() and 0xff,
                regVal = bytes[pos + 2].toInt() and 0xff,
                stringId = bytes[pos + 3].toInt() and 0xff,
                length = 4,
            )
            OP_PUT_NEW_OWN_BY_ID -> PutNewOwnIdAccess(
                regObj = bytes[pos + 1].toInt() and 0xff,
                regVal = bytes[pos + 2].toInt() and 0xff,
                stringId = HermesHbc96.readU16Le(bytes, pos + 3),
                length = 5,
            )
            OP_PUT_NEW_OWN_BY_ID_LONG -> {
                val id = HermesHbc96.readU32Le(bytes, pos + 3)
                if (id > Int.MAX_VALUE) null else PutNewOwnIdAccess(
                    regObj = bytes[pos + 1].toInt() and 0xff,
                    regVal = bytes[pos + 2].toInt() and 0xff,
                    stringId = id.toInt(),
                    length = 7,
                )
            }
            else -> null
        }
    }

    fun readLoadConstString(bytes: ByteArray, pos: Int): Triple<Int, Int, Int>? {
        return when (bytes[pos]) {
            HermesHbc96.OP_LOAD_CONST_STRING -> Triple(
                bytes[pos + 1].toInt() and 0xff,
                HermesHbc96.readU16Le(bytes, pos + 2),
                4,
            )
            HermesHbc96.OP_LOAD_CONST_STRING_LONG_INDEX -> {
                val id = HermesHbc96.readU32Le(bytes, pos + 2)
                if (id > Int.MAX_VALUE) null else Triple(
                    bytes[pos + 1].toInt() and 0xff,
                    id.toInt(),
                    6,
                )
            }
            else -> null
        }
    }

    fun readCreateClosure(bytes: ByteArray, pos: Int): ClosureCreate? {
        return when (bytes[pos]) {
            OP_CREATE_CLOSURE -> ClosureCreate(
                regDst = bytes[pos + 1].toInt() and 0xff,
                regEnv = bytes[pos + 2].toInt() and 0xff,
                functionId = HermesHbc96.readU16Le(bytes, pos + 3),
                length = 5,
            )
            OP_CREATE_CLOSURE_LONG_INDEX -> {
                val fnId = HermesHbc96.readU32Le(bytes, pos + 3)
                if (fnId > Int.MAX_VALUE) null else ClosureCreate(
                    regDst = bytes[pos + 1].toInt() and 0xff,
                    regEnv = bytes[pos + 2].toInt() and 0xff,
                    functionId = fnId.toInt(),
                    length = 7,
                )
            }
            else -> null
        }
    }

    fun readStoreToEnvironment(bytes: ByteArray, pos: Int): EnvStore? {
        return when (bytes[pos]) {
            OP_STORE_TO_ENVIRONMENT -> EnvStore(
                regEnv = bytes[pos + 1].toInt() and 0xff,
                envSlot = bytes[pos + 2].toInt() and 0xff,
                regVal = bytes[pos + 3].toInt() and 0xff,
                length = 4,
            )
            OP_STORE_TO_ENVIRONMENT_L -> EnvStore(
                regEnv = bytes[pos + 1].toInt() and 0xff,
                envSlot = HermesHbc96.readU16Le(bytes, pos + 2),
                regVal = bytes[pos + 4].toInt() and 0xff,
                length = 5,
            )
            else -> null
        }
    }

    fun overwriteWithJmpLongAndPad(
        code: ByteArray,
        patchOffset: Int,
        replacedLength: Int,
        targetOffset: Int,
    ) {
        require(replacedLength >= 5) { "JmpLong splice requires >= 5 bytes, got $replacedLength." }
        code[patchOffset] = OP_JMP_LONG
        HermesHbc96.writeI32Le(code, patchOffset + 1, targetOffset - patchOffset)
        for (i in 5 until replacedLength) {
            code[patchOffset + i] = HermesHbc96.OP_UNREACHABLE
        }
    }

    /** Builds small bytecode snippets or relocated tails with symbolic or absolute jump fixups. */
    class Builder(private val baseFunctionOffset: Int = 0) {
        private val out = ByteArrayOutputStream()
        private val labels = LinkedHashMap<String, Int>()
        private val fixups = ArrayList<JumpFixup>()

        private data class JumpFixup(
            val instrOffset: Int,
            val dispOffset: Int,
            val label: String?,
            val absoluteTarget: Int?,
        )

        val size: Int
            get() = out.size()

        fun label(name: String) {
            labels[name] = out.size()
        }

        fun u8(vararg values: Int) {
            for (v in values) {
                require(v in 0..0xff) { "Byte operand out of range: $v." }
                out.write(v)
            }
        }

        fun raw(bytes: ByteArray) {
            out.write(bytes)
        }

        fun op(opcode: Byte, vararg operands: Int) {
            out.write(opcode.toInt() and 0xff)
            u8(*operands)
        }

        fun loadConstDouble(reg: Int, value: Double) {
            op(OP_LOAD_CONST_DOUBLE, reg)
            val bits = java.lang.Double.doubleToRawLongBits(value)
            for (shift in 0 until 64 step 8) {
                out.write(((bits ushr shift) and 0xffL).toInt())
            }
        }

        fun loadConstString(reg: Int, stringId: Int) {
            if (stringId <= 0xffff) {
                op(HermesHbc96.OP_LOAD_CONST_STRING, reg, stringId and 0xff, (stringId ushr 8) and 0xff)
            } else {
                op(HermesHbc96.OP_LOAD_CONST_STRING_LONG_INDEX, reg)
                writeI32(stringId)
            }
        }

        fun getById(regDst: Int, regObj: Int, cacheIdx: Int, stringId: Int) {
            require(cacheIdx in 1..0xff) { "Invalid read cache index: $cacheIdx." }
            when {
                stringId <= 0xff -> op(OP_GET_BY_ID_SHORT, regDst, regObj, cacheIdx, stringId)
                stringId <= 0xffff -> op(OP_GET_BY_ID, regDst, regObj, cacheIdx, stringId and 0xff, (stringId ushr 8) and 0xff)
                else -> {
                    op(OP_GET_BY_ID_LONG, regDst, regObj, cacheIdx)
                    writeI32(stringId)
                }
            }
        }

        fun tryGetById(regDst: Int, regObj: Int, cacheIdx: Int, stringId: Int) {
            require(cacheIdx in 1..0xff) { "Invalid read cache index: $cacheIdx." }
            if (stringId <= 0xffff) {
                op(OP_TRY_GET_BY_ID, regDst, regObj, cacheIdx, stringId and 0xff, (stringId ushr 8) and 0xff)
            } else {
                op(OP_TRY_GET_BY_ID_LONG, regDst, regObj, cacheIdx)
                writeI32(stringId)
            }
        }

        fun putNewOwnById(regObj: Int, regVal: Int, stringId: Int) {
            when {
                stringId <= 0xff -> op(OP_PUT_NEW_OWN_BY_ID_SHORT, regObj, regVal, stringId)
                stringId <= 0xffff -> op(OP_PUT_NEW_OWN_BY_ID, regObj, regVal, stringId and 0xff, (stringId ushr 8) and 0xff)
                else -> {
                    op(OP_PUT_NEW_OWN_BY_ID_LONG, regObj, regVal)
                    writeI32(stringId)
                }
            }
        }

        fun loadFromEnvironment(regDst: Int, regEnv: Int, slot: Int) {
            if (slot <= 0xff) {
                op(OP_LOAD_FROM_ENVIRONMENT, regDst, regEnv, slot)
            } else {
                op(OP_LOAD_FROM_ENVIRONMENT_L, regDst, regEnv, slot and 0xff, (slot ushr 8) and 0xff)
            }
        }

        fun storeToEnvironment(regEnv: Int, slot: Int, regVal: Int) {
            if (slot <= 0xff) {
                op(OP_STORE_TO_ENVIRONMENT, regEnv, slot, regVal)
            } else {
                op(OP_STORE_TO_ENVIRONMENT_L, regEnv, slot and 0xff, (slot ushr 8) and 0xff, regVal)
            }
        }

        fun jmpLongToOffset(absoluteTargetInFunction: Int) {
            val instrOff = out.size()
            out.write(OP_JMP_LONG.toInt() and 0xff)
            val dispOff = out.size()
            writeI32(0)
            fixups.add(JumpFixup(instrOff, dispOff, label = null, absoluteTarget = absoluteTargetInFunction))
        }

        fun jumpLong(opcode: Byte, label: String, vararg regOperands: Int) {
            val instrOff = out.size()
            out.write(opcode.toInt() and 0xff)
            val dispOff = out.size()
            writeI32(0)
            u8(*regOperands)
            fixups.add(JumpFixup(instrOff, dispOff, label = label, absoluteTarget = null))
        }

        fun jumpLongToOffset(opcode: Byte, absoluteTargetInFunction: Int, vararg regOperands: Int) {
            val instrOff = out.size()
            out.write(opcode.toInt() and 0xff)
            val dispOff = out.size()
            writeI32(0)
            u8(*regOperands)
            fixups.add(JumpFixup(instrOff, dispOff, label = null, absoluteTarget = absoluteTargetInFunction))
        }

        fun build(): ByteArray {
            val bytes = out.toByteArray()
            for (fixup in fixups) {
                val targetAbs = fixup.absoluteTarget
                    ?: (baseFunctionOffset + (labels[fixup.label] ?: error("Undefined jump label '${fixup.label}'.")))
                val instrAbs = baseFunctionOffset + fixup.instrOffset
                HermesHbc96.writeI32Le(bytes, fixup.dispOffset, targetAbs - instrAbs)
            }
            return bytes
        }

        private fun writeI32(value: Int) {
            out.write(value and 0xff)
            out.write((value ushr 8) and 0xff)
            out.write((value ushr 16) and 0xff)
            out.write((value ushr 24) and 0xff)
        }
    }
}
