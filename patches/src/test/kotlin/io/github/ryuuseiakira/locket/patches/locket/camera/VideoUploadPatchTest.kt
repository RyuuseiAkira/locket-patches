// patches/src/test/kotlin/io/github/ryuuseiakira/locket/patches/locket/camera/VideoUploadPatchTest.kt
// Kotlin / kotlin.test + JUnit (JVM 11) / Unit tests for VideoUploadPatch and EnableCameraRollVideoUpload

package io.github.ryuuseiakira.locket.patches.locket.camera

import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.locket.gold.unlockGoldPatch
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class VideoUploadPatchTest {
    @Test
    fun `patch declares metadata compatibility and gold plus spoof dependencies`() {
        assertEquals("Upload videos from camera roll", videoUploadPatch.name)
        assertTrue(videoUploadPatch.default)
        assertEquals(1, videoUploadPatch.compatibility?.size)
        assertEquals("com.locket.Locket", videoUploadPatch.compatibility?.single()?.packageName)
        assertEquals(2, videoUploadPatch.dependencies.size)
        assertTrue(spoofSignaturePatch in videoUploadPatch.dependencies)
        assertTrue(unlockGoldPatch in videoUploadPatch.dependencies)
    }

    @Test
    fun `enable camera roll video upload rewrites all three stages and composes cleanly`() {
        val fixture = buildSyntheticVideoBundle()
        val result = HermesHbc96.patch(
            bundle = fixture.bytes,
            mutations = listOf(
                HermesHbc96.Mutation.EnableCameraRollVideoUpload(),
                HermesHbc96.Mutation.FunctionEarlyReturn(
                    functionName = "extraGuard",
                    replacement = byteArrayOf(HermesHbc96.OP_LOAD_CONST_TRUE, 0, HermesHbc96.OP_RET, 0),
                ),
            ),
        )

        assertEquals(5, result.appliedSites.size)
        val patched = result.bytes
        assertTrue(patched.size > fixture.bytes.size)
        assertEquals(patched.size.toLong(), u32Le(patched, 0x20))

        // Verify trailing SHA-1 integrity.
        val contentEnd = patched.size - HermesHbc96.SHA1_SIZE
        assertContentEquals(
            sha1(patched, contentEnd),
            patched.copyOfRange(contentEnd, patched.size),
        )

        // Stage A: MediaTypeOptions.Images rewritten to All.
        val mediaTypeSite = result.appliedSites[0]
        assertEquals(fixture.useCameraRollInitIdx, mediaTypeSite.functionIndex)
        val patchedMediaTypeId = when (mediaTypeSite.byteCount) {
            1 -> patched[mediaTypeSite.patchOffset].toInt() and 0xff
            2 -> u16Le(patched, mediaTypeSite.patchOffset)
            4 -> i32Le(patched, mediaTypeSite.patchOffset)
            else -> throw AssertionError("Unexpected operand width ${mediaTypeSite.byteCount}")
        }
        assertEquals(fixture.strId("All"), patchedMediaTypeId)

        // Stage B1: pre-transcode maxFileSizeBytes raised to 512 MiB.
        val maxSizeSite = result.appliedSites[1]
        assertEquals(fixture.openCameraRollIdx, maxSizeSite.functionIndex)
        assertEquals(HermesHbc96.DEFAULT_VIDEO_PICKER_MAX_FILE_BYTES, i32Le(patched, maxSizeSite.patchOffset))

        // Stage B2: openCameraRoll 16-byte in-place replacement uses safe scratch register and bumped read cache.
        val fileTypeSite = result.appliedSites[2]
        assertEquals(16, fileTypeSite.byteCount)
        assertEquals(HermesHbc96.OP_LOAD_CONST_STRING, patched[fileTypeSite.patchOffset])
        val tagScratch = fileTypeSite.register
        assertEquals(HermesHbc96.OP_GET_BY_ID_SHORT, patched[fileTypeSite.patchOffset + 4])
        assertEquals(tagScratch, patched[fileTypeSite.patchOffset + 5].toInt() and 0xff)
        assertEquals(fixture.strId("type"), patched[fileTypeSite.patchOffset + 8].toInt() and 0xff)
        assertEquals(HermesHbc96.OP_PUT_NEW_OWN_BY_ID_SHORT, patched[fileTypeSite.patchOffset + 9])
        assertEquals(fixture.strId("fileType"), patched[fileTypeSite.patchOffset + 12].toInt() and 0xff)
        val openCamHeaderW3 = i32Le(patched, HermesHbc96.HEADER_SIZE + fixture.openCameraRollIdx * 16 + 12)
        val bumpedOpenCamCache = (openCamHeaderW3 ushr 8) and 0xff
        assertEquals(3, bumpedOpenCamCache)

        // Stage C: Home onSuccess relocated to 4-byte aligned EOF before SHA-1 footer with frameSize >= 16.
        val onSuccessSite = result.appliedSites[3]
        assertEquals(fixture.onSuccessIdx, onSuccessSite.functionIndex)
        assertEquals(0, onSuccessSite.patchOffset and 3)
        assertTrue(onSuccessSite.patchOffset >= fixture.bytes.size - HermesHbc96.SHA1_SIZE)
        assertTrue(onSuccessSite.register >= 16)

        val onSuccessHdrOff = HermesHbc96.HEADER_SIZE + fixture.onSuccessIdx * 16
        val hdrW0 = i32Le(patched, onSuccessHdrOff)
        val hdrW1 = i32Le(patched, onSuccessHdrOff + 4)
        val hdrW2 = i32Le(patched, onSuccessHdrOff + 8)
        assertEquals(onSuccessSite.patchOffset, hdrW0 and 0x1ffffff)
        assertEquals(onSuccessSite.byteCount, hdrW1 and 0x7fff)
        assertEquals(onSuccessSite.register, (hdrW2 ushr 25) and 0x7f)

        // Relocated prologue starts with LoadParam r1, 1; GetById r2, r1, c, fileType; LoadConstString r3, video; JStrictNotEqualLong.
        val relocStart = onSuccessSite.patchOffset
        assertEquals(HermesHbc96.OP_LOAD_PARAM, patched[relocStart])
        assertEquals(1, patched[relocStart + 2].toInt() and 0xff)

        // Secondary non-video mutation composed on top still landed.
        val extraSite = result.appliedSites[4]
        assertEquals(fixture.extraGuardIdx, extraSite.functionIndex)
        assertNotEquals(0, extraSite.byteCount)
    }

    @Test
    fun `enable camera roll video upload rejects missing anchor string`() {
        val fixture = buildSyntheticVideoBundle(omitString = "Home-onRecordingFinished")
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(fixture.bytes, HermesHbc96.Mutation.EnableCameraRollVideoUpload())
        }
    }

    @Test
    fun `enable camera roll video upload fails closed when onSuccess carries exception handlers`() {
        val fixture = buildSyntheticVideoBundle(onSuccessFlags = 0x0d) // 0x05 | 0x08 (hasExceptionHandler)
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(fixture.bytes, HermesHbc96.Mutation.EnableCameraRollVideoUpload())
        }
    }

    @Test
    fun `enable camera roll video upload fails closed on ambiguous MediaTypeOptions site`() {
        val fixture = buildSyntheticVideoBundle(duplicateStageA = true)
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(fixture.bytes, HermesHbc96.Mutation.EnableCameraRollVideoUpload())
        }
    }

    @Test
    fun `non positive maxFileSizeBytes fails fast`() {
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.Mutation.EnableCameraRollVideoUpload(maxFileSizeBytes = 0)
        }
    }

    private class BundleFixture(
        val bytes: ByteArray,
        val stringMap: Map<String, Int>,
        val useCameraRollInitIdx: Int,
        val openCameraRollIdx: Int,
        val onSuccessIdx: Int,
        val extraGuardIdx: Int,
    ) {
        fun strId(value: String): Int = stringMap.getValue(value)
    }

    private fun buildSyntheticVideoBundle(
        omitString: String? = null,
        onSuccessFlags: Int = 0x05,
        duplicateStageA: Boolean = false,
    ): BundleFixture {
        val allStrings = listOf(
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
            "extraGuard",
        ).filter { it != omitString }

        val ids = HashMap<String, Int>(allStrings.size * 2)
        allStrings.forEachIndexed { idx, s -> ids[s] = idx }
        fun id(s: String): Int = ids[s] ?: 0

        val useCameraRollInitCode = byteArrayOf(
            HermesHbc96.OP_LOAD_CONST_STRING, 0, id("useCameraRoll").toByte(), 0,
            HermesHbc96.OP_LOAD_CONST_STRING, 1, id("getFileSize").toByte(), 0,
            HermesHbc96.OP_GET_BY_ID_SHORT, 3, 2, 0, id("MediaTypeOptions").toByte(),
            HermesHbc96.OP_GET_BY_ID_SHORT, 3, 3, 1, id("Images").toByte(),
            HermesHbc96.OP_PUT_BY_ID, 4, 3, 0, id("mediaTypes").toByte(), 0,
            HermesHbc96.OP_RET, 0,
        )

        val extraInitDupCode = if (!duplicateStageA) {
            byteArrayOf(HermesHbc96.OP_RET, 0)
        } else {
            useCameraRollInitCode
        }

        // openCameraRoll (frameSize=20 -> local regs 0..11; r11 reserved for safe scratch):
        // LoadFromEnvironment r9, r8, 6 (4B) + GetById r9, r9, 1, 'MediaTypes' (6B) + GetById r9, r9, 2, 'cameraRollImage' (6B) = 16 bytes
        val openCameraRollCode = ByteArrayOutputStream().apply {
            fun sRef(name: String) {
                write(HermesHbc96.OP_LOAD_CONST_STRING.toInt())
                write(0)
                writeU16LeStream(this, id(name))
            }
            sRef("requestMediaLibraryPermissionsAsync")
            sRef("launchImageLibraryAsync")
            sRef("too_large_file_error_message")
            sRef("useCameraRoll - openCameraRoll")
            write(HermesHbc96.OP_LOAD_CONST_INT.toInt())
            write(6)
            writeI32LeStream(this, 104_857_600)
            write(HermesHbc96.OP_JGREATER.toInt())
            write(6)
            write(7)
            write(6)
            write(HermesHbc96.OP_LOAD_CONST_ZERO.toInt())
            write(0)
            write(HermesHbc96.OP_LOAD_FROM_ENVIRONMENT.toInt())
            write(9)
            write(8)
            write(6)
            write(HermesHbc96.OP_GET_BY_ID.toInt())
            write(9)
            write(9)
            write(1)
            writeU16LeStream(this, id("MediaTypes"))
            write(HermesHbc96.OP_GET_BY_ID.toInt())
            write(9)
            write(9)
            write(2)
            writeU16LeStream(this, id("cameraRollImage"))
            write(HermesHbc96.OP_PUT_NEW_OWN_BY_ID_SHORT.toInt())
            write(6)
            write(9)
            write(id("type"))
            write(HermesHbc96.OP_GET_BY_ID_SHORT.toInt())
            write(9)
            write(10)
            write(2)
            write(id("uri"))
            write(HermesHbc96.OP_RET.toInt())
            write(6)
        }.toByteArray()

        // Home: creates onSuccess (fn#3) via Call3, sets prop 'onSuccess', creates wrapper (fn#4)
        val homeCode = ByteArrayOutputStream().apply {
            write(HermesHbc96.OP_CREATE_ENVIRONMENT.toInt())
            write(11)
            write(HermesHbc96.OP_CREATE_CLOSURE.toInt())
            write(2)
            write(11)
            writeU16LeStream(this, 3)
            write(HermesHbc96.OP_CALL3.toInt())
            write(4)
            write(5)
            write(6)
            write(2)
            write(7)
            write(HermesHbc96.OP_GET_BY_ID_SHORT.toInt())
            write(5)
            write(6)
            write(0)
            write(id("useCameraRoll"))
            write(HermesHbc96.OP_NEW_OBJECT.toInt())
            write(1)
            write(HermesHbc96.OP_PUT_NEW_OWN_BY_ID_SHORT.toInt())
            write(1)
            write(4)
            write(id("onSuccess"))
            write(HermesHbc96.OP_CREATE_CLOSURE.toInt())
            write(8)
            write(11)
            writeU16LeStream(this, 4)
            write(HermesHbc96.OP_RET.toInt())
            write(0)
        }.toByteArray()

        // onSuccess (fn#3): prologue + startLoading block + MEDIA_PROCESSING block + Ret
        val onSuccessCode = ByteArrayOutputStream().apply {
            write(HermesHbc96.OP_GET_ENVIRONMENT.toInt())
            write(1)
            write(0)
            write(HermesHbc96.OP_LOAD_CONST_UNDEFINED.toInt())
            write(0)
            write(HermesHbc96.OP_LOAD_CONST_STRING.toInt())
            write(2)
            writeU16LeStream(this, id(""))
            write(HermesHbc96.OP_LOAD_CONST_STRING.toInt())
            write(2)
            writeU16LeStream(this, id("reset"))
            write(HermesHbc96.OP_LOAD_FROM_ENVIRONMENT.toInt())
            write(2)
            write(1)
            write(14)
            write(HermesHbc96.OP_GET_BY_ID_SHORT.toInt())
            write(3)
            write(2)
            write(1)
            write(id("current"))
            write(HermesHbc96.OP_LOAD_CONST_NULL.toInt())
            write(2)
            write(HermesHbc96.OP_JEQUAL.toInt())
            write(13)
            write(3)
            write(2)
            write(HermesHbc96.OP_GET_BY_ID_SHORT.toInt())
            write(2)
            write(3)
            write(2)
            write(id("startLoading"))
            write(HermesHbc96.OP_CALL1.toInt())
            write(2)
            write(2)
            write(3)
            write(HermesHbc96.OP_LOAD_FROM_ENVIRONMENT.toInt())
            write(2)
            write(1)
            write(65)
            write(HermesHbc96.OP_GET_ENVIRONMENT.toInt())
            write(1)
            write(1)
            write(HermesHbc96.OP_LOAD_FROM_ENVIRONMENT.toInt())
            write(1)
            write(1)
            write(29)
            write(HermesHbc96.OP_GET_BY_ID_SHORT.toInt())
            write(1)
            write(1)
            write(3)
            write(id("HomeCaptureStage"))
            write(HermesHbc96.OP_GET_BY_ID_SHORT.toInt())
            write(1)
            write(1)
            write(4)
            write(id("MEDIA_PROCESSING"))
            write(HermesHbc96.OP_CALL2.toInt())
            write(1)
            write(2)
            write(0)
            write(1)
            write(HermesHbc96.OP_RET.toInt())
            write(0)
        }.toByteArray()

        val wrapperCode = byteArrayOf(
            HermesHbc96.OP_CREATE_ENVIRONMENT, 1,
            HermesHbc96.OP_CREATE_CLOSURE, 2, 1, 5, 0,
            HermesHbc96.OP_RET, 2,
        )

        val factoryCode = byteArrayOf(
            HermesHbc96.OP_CREATE_ENVIRONMENT, 0,
            HermesHbc96.OP_GET_ENVIRONMENT, 1, 2,
            HermesHbc96.OP_CREATE_GENERATOR_CLOSURE, 1, 0, 6, 0,
            HermesHbc96.OP_CREATE_CLOSURE, 0, 0, 8, 0,
            HermesHbc96.OP_RET, 0,
        )

        val genWrapperCode = byteArrayOf(
            HermesHbc96.OP_CREATE_GENERATOR, 0, 0, 7, 0,
            HermesHbc96.OP_RET, 0,
        )

        val genBodyCode = ByteArrayOutputStream().apply {
            write(HermesHbc96.OP_GET_ENVIRONMENT.toInt())
            write(1)
            write(3)
            for (s in listOf("generateCroppedVideo", "Home-onRecordingFinished", "video_recording_error")) {
                write(HermesHbc96.OP_LOAD_CONST_STRING.toInt())
                write(0)
                writeU16LeStream(this, id(s))
            }
            write(HermesHbc96.OP_RET.toInt())
            write(0)
        }.toByteArray()

        val onRecNamedCode = byteArrayOf(HermesHbc96.OP_RET, 0)

        val extraGuardCode = byteArrayOf(
            HermesHbc96.OP_LOAD_CONST_FALSE, 0,
            HermesHbc96.OP_RET, 0,
        )

        val funcSpecs = mutableListOf(
            Triple(id(""), 13, 0x05) to useCameraRollInitCode,
            Triple(id("?anon_0_"), 20, 0x0e) to openCameraRollCode,
            Triple(id("Home"), 20, 0x05) to homeCode,
            Triple(id(""), 13, onSuccessFlags) to onSuccessCode,
            Triple(id(""), 12, 0x05) to wrapperCode,
            Triple(id(""), 12, 0x06) to factoryCode,
            Triple(id(""), 12, 0x06) to genWrapperCode,
            Triple(id("?anon_0_"), 12, 0x0e) to genBodyCode,
            Triple(id("onRecordingFinished"), 12, 0x05) to onRecNamedCode,
            Triple(id("extraGuard"), 10, 0x05) to extraGuardCode,
        )
        val extraGuardIdx = 9
        if (duplicateStageA) {
            funcSpecs.add(Triple(id(""), 13, 0x05) to extraInitDupCode)
        }

        val strStorage = ByteArrayOutputStream()
        val smallStrings = ByteArrayOutputStream()
        for (s in allStrings) {
            val bytes = s.toByteArray(Charsets.ISO_8859_1)
            val off = strStorage.size()
            strStorage.write(bytes)
            val packed = ((bytes.size and 0xff) shl 24) or ((off and 0x7fffff) shl 1)
            writeI32LeStream(smallStrings, packed)
        }

        val funcTableSize = funcSpecs.size * 16
        val kindOff = align4Int(HermesHbc96.HEADER_SIZE + funcTableSize)
        val identOff = align4Int(kindOff + 4)
        val smallStrOff = align4Int(identOff)
        val ovfStrOff = align4Int(smallStrOff + allStrings.size * 4)
        val strStorageOff = align4Int(ovfStrOff)
        val bytecodeStart = align4Int(strStorageOff + strStorage.size())

        val bodyOffsets = IntArray(funcSpecs.size)
        var cursor = bytecodeStart
        for (i in funcSpecs.indices) {
            bodyOffsets[i] = cursor
            cursor += funcSpecs[i].second.size
        }
        val contentEnd = cursor
        val totalSize = contentEnd + HermesHbc96.SHA1_SIZE
        val buf = ByteArray(totalSize)

        writeU64Le(buf, 0x00, HermesHbc96.HBC_MAGIC)
        writeI32Le(buf, 0x08, HermesHbc96.HBC_VERSION)
        writeI32Le(buf, 0x20, totalSize)
        writeI32Le(buf, 0x28, funcSpecs.size)
        writeI32Le(buf, 0x2c, 1)
        writeI32Le(buf, 0x30, 0)
        writeI32Le(buf, 0x34, allStrings.size)
        writeI32Le(buf, 0x38, 0)
        writeI32Le(buf, 0x3c, strStorage.size())

        for (i in funcSpecs.indices) {
            val (hdrTuple, code) = funcSpecs[i]
            val (nameId, frameSize, flags) = hdrTuple
            val hOff = HermesHbc96.HEADER_SIZE + i * 16
            val rCache = if (i == 1) 2 else if (i == 3) 4 else 1
            val w0 = (bodyOffsets[i] and 0x1ffffff) or (2 shl 25)
            val w1 = (code.size and 0x7fff) or ((nameId and 0x1ffff) shl 15)
            val w2 = (frameSize and 0x7f) shl 25
            val w3 = (rCache shl 8) or ((flags and 0xff) shl 24)
            writeI32Le(buf, hOff, w0)
            writeI32Le(buf, hOff + 4, w1)
            writeI32Le(buf, hOff + 8, w2)
            writeI32Le(buf, hOff + 12, w3)
            System.arraycopy(code, 0, buf, bodyOffsets[i], code.size)
        }

        val strTbl = smallStrings.toByteArray()
        System.arraycopy(strTbl, 0, buf, smallStrOff, strTbl.size)
        val rawStr = strStorage.toByteArray()
        System.arraycopy(rawStr, 0, buf, strStorageOff, rawStr.size)

        val digest = sha1(buf, contentEnd)
        System.arraycopy(digest, 0, buf, contentEnd, HermesHbc96.SHA1_SIZE)

        return BundleFixture(
            bytes = buf,
            stringMap = ids,
            useCameraRollInitIdx = 0,
            openCameraRollIdx = 1,
            onSuccessIdx = 3,
            extraGuardIdx = extraGuardIdx,
        )
    }

    private fun align4Int(v: Int): Int = (v + 3) and -4

    private fun u16Le(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8)

    private fun i32Le(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or
            ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or
            ((b[off + 3].toInt() and 0xff) shl 24)

    private fun u32Le(b: ByteArray, off: Int): Long = i32Le(b, off).toLong() and 0xffffffffL

    private fun writeI32Le(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xff).toByte()
        b[off + 1] = ((v ushr 8) and 0xff).toByte()
        b[off + 2] = ((v ushr 16) and 0xff).toByte()
        b[off + 3] = ((v ushr 24) and 0xff).toByte()
    }

    private fun writeU64Le(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) {
            b[off + i] = ((v ushr (i * 8)) and 0xffL).toByte()
        }
    }

    private fun writeU16LeStream(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xff)
        out.write((v ushr 8) and 0xff)
    }

    private fun writeI32LeStream(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xff)
        out.write((v ushr 8) and 0xff)
        out.write((v ushr 16) and 0xff)
        out.write((v ushr 24) and 0xff)
    }

    private fun sha1(b: ByteArray, length: Int): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        md.update(b, 0, length)
        return md.digest()
    }
}
