// patches/src/test/kotlin/io/github/ryuuseiakira/locket/patches/locket/gold/HermesBundlePatcherTest.kt
// Kotlin / JUnit 5 test suite for HermesBundlePatcher

package io.github.ryuuseiakira.locket.patches.locket.gold

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HermesBundlePatcherTest {

    @Test
    fun `patches LoadConstString Call2 sequence and recomputes trailing SHA-1`() {
        val prefix = byteArrayOf(0x29, 0x00, 0x00, 0x51, 0x02, 0x01, 0x00)
        val seq = byteArrayOf(
            0x37, 0x01, 0x02, 0x03, 0x01, 0x00, // GetById r1, r2, cache=3, str#1 ("getBoolean")
            0x73, 0x00, 0x02, 0x00,             // LoadConstString r0, str#2 ("android_gold_subscription_override")
            0x53, 0x04, 0x01, 0x02, 0x00,       // Call2 r4, r1, r2, r0
            0x5c, 0x04,                         // Ret r4
        )
        val bundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = prefix + seq)),
        )

        val result = HermesBundlePatcher.patch(bundle)
        assertEquals(0, result.functionIndex)
        assertEquals(4, result.returnRegister)

        val expectedTail = byteArrayOf(0x78, 0x04, 0x5c, 0x04, 0x00)
        val actualSlice = result.bytes.copyOfRange(result.patchOffset, result.patchOffset + 5)
        assertTrue(expectedTail.contentEquals(actualSlice))

        val contentEnd = result.bytes.size - HermesBundlePatcher.SHA1_SIZE
        val recomputedSha1 = MessageDigest.getInstance("SHA-1").apply {
            update(result.bytes, 0, contentEnd)
        }.digest()
        val storedSha1 = result.bytes.copyOfRange(contentEnd, result.bytes.size)
        assertTrue(recomputedSha1.contentEquals(storedSha1))
    }

    @Test
    fun `patches LoadConstStringLongIndex when key string index exceeds uint16`() {
        val strings = MutableList(65540) { index ->
            when (index) {
                0 -> "androidGoldSubscriptionOverride"
                1 -> "getBoolean"
                65539 -> "android_gold_subscription_override"
                else -> "s"
            }
        }
        val keyId = 65539
        val seq = byteArrayOf(
            0x37, 0x01, 0x02, 0x00, 0x01, 0x00,
            0x74, 0x05,
            (keyId and 0xff).toByte(),
            ((keyId ushr 8) and 0xff).toByte(),
            ((keyId ushr 16) and 0xff).toByte(),
            ((keyId ushr 24) and 0xff).toByte(),
            0x53, 0x00, 0x01, 0x02, 0x05,
            0x5c, 0x00,
        )
        val bundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(SyntheticFunction(nameId = 0, code = seq)),
        )

        val result = HermesBundlePatcher.patch(bundle)
        assertEquals(0, result.returnRegister)
        val actualSlice = result.bytes.copyOfRange(result.patchOffset, result.patchOffset + 5)
        assertTrue(byteArrayOf(0x78, 0x00, 0x5c, 0x00, 0x00).contentEquals(actualSlice))
    }

    @Test
    fun `patches function resolved via LargeFuncHeader overflow entry`() {
        val seq = byteArrayOf(
            0x37, 0x02, 0x03, 0x01, 0x01, 0x00,
            0x73, 0x04, 0x02, 0x00,
            0x53, 0x07, 0x02, 0x03, 0x04,
            0x5c, 0x07,
        )
        val bundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq, useLargeHeader = true)),
        )

        val result = HermesBundlePatcher.patch(bundle)
        assertEquals(7, result.returnRegister)
        val actualSlice = result.bytes.copyOfRange(result.patchOffset, result.patchOffset + 5)
        assertTrue(byteArrayOf(0x78, 0x07, 0x5c, 0x07, 0x00).contentEquals(actualSlice))
    }

    @Test
    fun `rejects unsupported Hermes bytecode version and corrupted SHA-1 footer`() {
        val seq = byteArrayOf(
            0x37, 0x01, 0x02, 0x00, 0x01, 0x00,
            0x73, 0x00, 0x02, 0x00,
            0x53, 0x00, 0x01, 0x02, 0x00,
            0x5c, 0x00,
        )
        val wrongVersionBundle = buildSyntheticBundle(
            version = 95,
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq)),
        )
        assertFailsWith<IllegalArgumentException> {
            HermesBundlePatcher.patch(wrongVersionBundle)
        }

        val corruptedFooterBundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq)),
        )
        corruptedFooterBundle[corruptedFooterBundle.lastIndex] =
            (corruptedFooterBundle[corruptedFooterBundle.lastIndex].toInt() xor 0xff).toByte()
        assertFailsWith<IllegalArgumentException> {
            HermesBundlePatcher.patch(corruptedFooterBundle)
        }
    }

    @Test
    fun `rejects bundle missing target function or containing ambiguous call sites`() {
        val seq = byteArrayOf(
            0x37, 0x01, 0x02, 0x00, 0x01, 0x00,
            0x73, 0x00, 0x02, 0x00,
            0x53, 0x00, 0x01, 0x02, 0x00,
            0x5c, 0x00,
        )
        val missingFnBundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override", "other"),
            functions = listOf(SyntheticFunction(nameId = 3, code = seq)),
        )
        assertFailsWith<IllegalArgumentException> {
            HermesBundlePatcher.patch(missingFnBundle)
        }

        val duplicateCallBundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq + seq)),
        )
        assertFailsWith<IllegalArgumentException> {
            HermesBundlePatcher.patch(duplicateCallBundle)
        }
    }

    @Test
    fun `matches expected output SHA-256 when real Locket bundle path is supplied`() {
        val bundlePath = System.getenv("LOCKET_BUNDLE_PATH")?.let(::File)?.takeIf(File::isFile) ?: return
        val expectedSha256 = System.getenv("LOCKET_EXPECTED_SHA256")

        val result = HermesBundlePatcher.patch(bundlePath.readBytes())
        if (!expectedSha256.isNullOrBlank()) {
            val actualSha256 = MessageDigest.getInstance("SHA-256")
                .digest(result.bytes)
                .joinToString("") { "%02x".format(it) }
            assertEquals(expectedSha256.lowercase(), actualSha256)
        }
    }

    private data class SyntheticFunction(
        val nameId: Int,
        val code: ByteArray,
        val useLargeHeader: Boolean = false,
    )

    private fun buildSyntheticBundle(
        version: Int = HermesBundlePatcher.HBC_VERSION,
        strings: List<String>,
        functions: List<SyntheticFunction>,
    ): ByteArray {
        val storage = ByteArrayOutputStream()
        val smallStrings = ByteArray(strings.size * 4)
        for ((idx, value) in strings.withIndex()) {
            val encoded = value.toByteArray(StandardCharsets.ISO_8859_1)
            val off = storage.size()
            storage.write(encoded)
            val entry = (off shl 1) or (encoded.size shl 24)
            writeI32Le(smallStrings, idx * 4, entry)
        }
        val storageBytes = storage.toByteArray()

        val funcTableSize = functions.size * 16
        val smallStrOff = align4(HermesBundlePatcher.HEADER_SIZE + funcTableSize)
        val storageOff = align4(smallStrOff + smallStrings.size)
        var cursor = align4(storageOff + storageBytes.size)

        val largeHeaderOffsets = IntArray(functions.size) { -1 }
        val codeOffsets = IntArray(functions.size)
        for ((idx, fn) in functions.withIndex()) {
            if (fn.useLargeHeader) {
                largeHeaderOffsets[idx] = cursor
                cursor += 32
            }
            codeOffsets[idx] = cursor
            cursor = align4(cursor + fn.code.size)
        }

        val totalSize = cursor + HermesBundlePatcher.SHA1_SIZE
        val out = ByteArray(totalSize)

        writeI64Le(out, 0x00, HermesBundlePatcher.HBC_MAGIC)
        writeI32Le(out, 0x08, version)
        writeI32Le(out, 0x20, totalSize)
        writeI32Le(out, 0x28, functions.size)
        writeI32Le(out, 0x34, strings.size)
        writeI32Le(out, 0x3c, storageBytes.size)

        System.arraycopy(smallStrings, 0, out, smallStrOff, smallStrings.size)
        System.arraycopy(storageBytes, 0, out, storageOff, storageBytes.size)

        for ((idx, fn) in functions.withIndex()) {
            val hOff = HermesBundlePatcher.HEADER_SIZE + idx * 16
            if (!fn.useLargeHeader) {
                val w0 = codeOffsets[idx] and 0x1ffffff
                val w1 = (fn.code.size and 0x7fff) or ((fn.nameId and 0x1ffff) shl 15)
                writeI32Le(out, hOff, w0)
                writeI32Le(out, hOff + 4, w1)
            } else {
                val lo = largeHeaderOffsets[idx]
                val w0 = lo and 0xffff
                val w2 = (lo ushr 16) and 0xffff
                val w3 = 0x20 shl 24 // overflowed flag bit
                writeI32Le(out, hOff, w0)
                writeI32Le(out, hOff + 8, w2)
                writeI32Le(out, hOff + 12, w3)

                writeI32Le(out, lo, codeOffsets[idx])
                writeI32Le(out, lo + 8, fn.code.size)
                writeI32Le(out, lo + 12, fn.nameId)
            }
            System.arraycopy(fn.code, 0, out, codeOffsets[idx], fn.code.size)
        }

        val contentEnd = totalSize - HermesBundlePatcher.SHA1_SIZE
        val digest = MessageDigest.getInstance("SHA-1").apply { update(out, 0, contentEnd) }.digest()
        System.arraycopy(digest, 0, out, contentEnd, HermesBundlePatcher.SHA1_SIZE)
        return out
    }

    private fun align4(v: Int): Int = (v + 3) and -4

    private fun writeI32Le(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = (value and 0xff).toByte()
        buf[offset + 1] = ((value ushr 8) and 0xff).toByte()
        buf[offset + 2] = ((value ushr 16) and 0xff).toByte()
        buf[offset + 3] = ((value ushr 24) and 0xff).toByte()
    }

    private fun writeI64Le(buf: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) {
            buf[offset + i] = ((value ushr (i * 8)) and 0xffL).toByte()
        }
    }
}
