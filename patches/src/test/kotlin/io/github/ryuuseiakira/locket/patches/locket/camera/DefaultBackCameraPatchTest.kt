// patches/src/test/kotlin/io/github/ryuuseiakira/locket/patches/locket/camera/DefaultBackCameraPatchTest.kt
// kotlin / DefaultBackCameraPatchTest / kotlin.test + JUnit / HermesHbc96 + DefaultBackCameraPatch

package io.github.ryuuseiakira.locket.patches.locket.camera

import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DefaultBackCameraPatchTest {
    @Test
    fun `patch metadata matches expected defaults`() {
        assertEquals("Default back camera", defaultBackCameraPatch.name)
        assertFalse(defaultBackCameraPatch.default)
        assertEquals(1, defaultBackCameraPatch.compatibility?.size)
        assertEquals("com.locket.Locket", defaultBackCameraPatch.compatibility?.single()?.packageName)
    }

    @Test
    fun `rewrites useState front string operand to back without altering string table`() {
        val strings = listOf("Home", "useState", "useCameraDevice", "cameraPosition", "front", "back")
        val strFront = 4
        val strBack = 5
        // GetByIdShort r34, r8, 25, useState(1) ; LoadConstString r14, front(4) ; Call2 r37, r34, r3, r14 ; Ret r37
        val homeCode = byteArrayOf(
            HermesHbc96.OP_GET_BY_ID_SHORT, 34, 8, 25, 1,
            HermesHbc96.OP_LOAD_CONST_STRING, 14, strFront.toByte(), 0,
            HermesHbc96.OP_CALL2, 37, 34, 3, 14,
            HermesHbc96.OP_LOAD_CONST_STRING, 15, 2, 0, // "useCameraDevice" ref
            HermesHbc96.OP_LOAD_CONST_STRING, 16, 3, 0, // "cameraPosition" ref
            HermesHbc96.OP_LOAD_CONST_STRING, 17, strBack.toByte(), 0, // "back" ref (kept untouched)
            HermesHbc96.OP_RET, 37,
        )
        // Decoy Home without camera strings
        val decoyCode = byteArrayOf(
            HermesHbc96.OP_GET_BY_ID_SHORT, 1, 2, 0, 1,
            HermesHbc96.OP_LOAD_CONST_STRING, 3, strFront.toByte(), 0,
            HermesHbc96.OP_CALL2, 4, 1, 2, 3,
            HermesHbc96.OP_RET, 4,
        )

        val bundle = buildSyntheticHbc(
            strings = strings,
            functions = listOf(
                SyntheticFunc(nameId = 0, code = decoyCode),
                SyntheticFunc(nameId = 0, code = homeCode),
            ),
        )

        val result = HermesHbc96.patch(
            bundle,
            HermesHbc96.Mutation.ReplaceCallStringConst(
                functionName = "Home",
                calleeName = "useState",
                fromValue = "front",
                toValue = "back",
                requiredStrings = listOf("useCameraDevice", "cameraPosition", "front", "back"),
            ),
        )

        val site = result.appliedSites.single()
        assertEquals(1, site.functionIndex)
        assertEquals(2, site.byteCount)
        assertEquals(14, site.register)

        // LoadConstString r14 operand now points to string ID 5 ("back")
        assertEquals(strBack.toByte(), result.bytes[site.patchOffset])
        assertEquals(0, result.bytes[site.patchOffset + 1])

        // String table must keep "front" intact for camera flip / toggles.
        assertTrue(String(result.bytes, StandardCharsets.US_ASCII).contains("front"))
        assertTrue(String(result.bytes, StandardCharsets.US_ASCII).contains("back"))

        // Trailing SHA-1 footer matches updated content.
        val contentEnd = result.bytes.size - 20
        val expectedHash = MessageDigest.getInstance("SHA-1").digest(result.bytes.copyOf(contentEnd))
        assertContentEquals(expectedHash, result.bytes.copyOfRange(contentEnd, result.bytes.size))
    }

    @Test
    fun `supports long LoadConstStringLongIndex and reversed LoadConstString before GetById`() {
        val strings = listOf("Home", "useState", "front", "back")
        // LoadConstStringLongIndex r5, front(2) ; GetById r1, r2, 7, useState(1) ; Call2 r9, r1, r2, r5 ; Ret r9
        val homeCode = byteArrayOf(
            HermesHbc96.OP_LOAD_CONST_STRING_LONG_INDEX, 5, 2, 0, 0, 0,
            HermesHbc96.OP_GET_BY_ID, 1, 2, 7, 1, 0,
            HermesHbc96.OP_CALL2, 9, 1, 2, 5,
            HermesHbc96.OP_RET, 9,
        )

        val bundle = buildSyntheticHbc(
            strings = strings,
            functions = listOf(SyntheticFunc(nameId = 0, code = homeCode)),
        )

        val result = HermesHbc96.patch(
            bundle,
            HermesHbc96.Mutation.ReplaceCallStringConst(
                functionName = "Home",
                calleeName = "useState",
                fromValue = "front",
                toValue = "back",
            ),
        )

        val site = result.appliedSites.single()
        assertEquals(4, site.byteCount)
        assertEquals(5, site.register)
        assertEquals(3.toByte(), result.bytes[site.patchOffset])
        assertEquals(0.toByte(), result.bytes[site.patchOffset + 1])
        assertEquals(0.toByte(), result.bytes[site.patchOffset + 2])
        assertEquals(0.toByte(), result.bytes[site.patchOffset + 3])
    }

    @Test
    fun `fails cleanly on ambiguous matches or identical source and target strings`() {
        val strings = listOf("Home", "useState", "front", "back")
        val duplicateCode = byteArrayOf(
            HermesHbc96.OP_GET_BY_ID_SHORT, 1, 2, 0, 1,
            HermesHbc96.OP_LOAD_CONST_STRING, 3, 2, 0,
            HermesHbc96.OP_CALL2, 4, 1, 2, 3,
            HermesHbc96.OP_GET_BY_ID_SHORT, 1, 2, 1, 1,
            HermesHbc96.OP_LOAD_CONST_STRING, 3, 2, 0,
            HermesHbc96.OP_CALL2, 4, 1, 2, 3,
            HermesHbc96.OP_RET, 4,
        )
        val bundle = buildSyntheticHbc(
            strings = strings,
            functions = listOf(SyntheticFunc(nameId = 0, code = duplicateCode)),
        )

        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(
                bundle,
                HermesHbc96.Mutation.ReplaceCallStringConst(
                    functionName = "Home",
                    calleeName = "useState",
                    fromValue = "front",
                    toValue = "back",
                ),
            )
        }

        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(
                bundle,
                HermesHbc96.Mutation.ReplaceCallStringConst(
                    functionName = "Home",
                    calleeName = "useState",
                    fromValue = "front",
                    toValue = "front",
                ),
            )
        }
    }

    private data class SyntheticFunc(val nameId: Int, val code: ByteArray)

    private fun buildSyntheticHbc(strings: List<String>, functions: List<SyntheticFunc>): ByteArray {
        val out = ByteArrayOutputStream()
        fun writeU32(v: Long) {
            for (i in 0 until 4) out.write(((v ushr (i * 8)) and 0xffL).toInt())
        }
        fun writeU64(v: Long) {
            for (i in 0 until 8) out.write(((v ushr (i * 8)) and 0xffL).toInt())
        }
        fun padAlign4() {
            while ((out.size() and 3) != 0) out.write(0)
        }

        val headerSize = 128
        val smallFuncSize = 16 * functions.size
        val funcTableEnd = headerSize + smallFuncSize
        val kindOff = (funcTableEnd + 3) and -4
        val identOff = kindOff // 0 stringKinds
        val smallStrOff = identOff // 0 identifiers
        val ovfStrOff = smallStrOff + 4 * strings.size
        val strStorageOff = ovfStrOff // 0 overflow strings

        val strBlob = ByteArrayOutputStream()
        val strMeta = ArrayList<Int>(strings.size)
        for (s in strings) {
            val bytes = s.toByteArray(StandardCharsets.US_ASCII)
            val off = strBlob.size()
            strBlob.write(bytes)
            val entry = ((bytes.size and 0xff) shl 24) or ((off and 0x7fffff) shl 1)
            strMeta.add(entry)
        }

        val strBytes = strBlob.toByteArray()
        val codeStart = (strStorageOff + strBytes.size + 3) and -4
        val funcOffsets = IntArray(functions.size)
        var cursor = codeStart
        for (i in functions.indices) {
            funcOffsets[i] = cursor
            cursor += functions[i].code.size
        }
        val contentEnd = cursor
        val totalSize = contentEnd + 20

        // 128-byte header
        writeU64(0x1f1903c103bc1fc6L) // magic
        writeU32(96L) // version
        out.write(ByteArray(20)) // sourceHash
        writeU32(totalSize.toLong()) // fileLength
        writeU32(0L) // globalCodeIndex
        writeU32(functions.size.toLong()) // functionCount
        writeU32(0L) // stringKindCount
        writeU32(0L) // identifierCount
        writeU32(strings.size.toLong()) // stringCount
        writeU32(0L) // overflowStringCount
        writeU32(strBytes.size.toLong()) // stringStorageSize
        while (out.size() < headerSize) out.write(0)

        for (i in functions.indices) {
            val f = functions[i]
            val offset = funcOffsets[i]
            val size = f.code.size
            // Word0: offset (25 bits) | paramCount (7 bits)
            writeU32((offset.toLong() and 0x1ffffffL) or (1L shl 25))
            // Word1: bytecodeSizeInBytes (15 bits) | functionName (17 bits)
            writeU32((size.toLong() and 0x7fffL) or ((f.nameId.toLong() and 0x1ffffL) shl 15))
            // Word2 & Word3: infoOffset / frameSize / flags
            writeU32(0L)
            writeU32(0L)
        }
        padAlign4()

        for (entry in strMeta) writeU32(entry.toLong() and 0xffffffffL)
        out.write(strBytes)
        padAlign4()
        for (f in functions) out.write(f.code)

        val content = out.toByteArray()
        val digest = MessageDigest.getInstance("SHA-1").digest(content)
        val full = ByteArray(totalSize)
        System.arraycopy(content, 0, full, 0, content.size)
        System.arraycopy(digest, 0, full, content.size, 20)
        return full
    }
}
