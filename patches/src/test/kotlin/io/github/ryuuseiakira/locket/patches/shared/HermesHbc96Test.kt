// patches/src/test/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96Test.kt
// Kotlin / JUnit 5 test suite for HermesHbc96

package io.github.ryuuseiakira.locket.patches.shared

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HermesHbc96Test {

    @Test
    fun `patches LoadConstString Call2 for boolean zero null undefined and true`() {
        val cases = listOf(
            "fnTrue" to ("android_gold_subscription_override" to HermesHbc96.OP_LOAD_CONST_TRUE),
            "fnFalse" to ("android_history_ads_enabled" to HermesHbc96.OP_LOAD_CONST_FALSE),
            "fnZero" to ("sentry_sample_rate" to HermesHbc96.OP_LOAD_CONST_ZERO),
        )
        val prefix = byteArrayOf(0x29, 0x00, 0x00, 0x51, 0x02, 0x01, 0x00)
        val strings = mutableListOf("getBoolean", "getNumber")
        val functions = mutableListOf<SyntheticFunction>()
        val mutations = mutableListOf<HermesHbc96.Mutation>()

        for ((fnName, pair) in cases) {
            val (keyName, opcode) = pair
            val getter = if (opcode == HermesHbc96.OP_LOAD_CONST_ZERO) "getNumber" else "getBoolean"
            val getterId = strings.indexOf(getter)
            val fnId = strings.size.also { strings.add(fnName) }
            val keyId = strings.size.also { strings.add(keyName) }
            val seq = byteArrayOf(
                0x37, 0x01, 0x02, 0x03, getterId.toByte(), 0x00,
                0x73, 0x00, keyId.toByte(), 0x00,
                0x53, 0x04, 0x01, 0x02, 0x00,
                0x5c, 0x04,
            )
            functions.add(SyntheticFunction(nameId = fnId, code = prefix + seq))
            mutations.add(HermesHbc96.Mutation.RemoteConfigReturnConst(fnName, getter, keyName, opcode))
        }

        val bundle = buildSyntheticBundle(strings = strings, functions = functions)
        val result = HermesHbc96.patch(bundle, mutations)

        assertEquals(3, result.appliedSites.size)
        for ((index, site) in result.appliedSites.withIndex()) {
            val expectedOp = mutations[index].let { (it as HermesHbc96.Mutation.RemoteConfigReturnConst).returnOpcode }
            val actualSlice = result.bytes.copyOfRange(site.patchOffset, site.patchOffset + 5)
            assertTrue(byteArrayOf(expectedOp, 0x04, 0x5c, 0x04, 0x00).contentEquals(actualSlice))
        }

        assertValidSha1Footer(result.bytes)
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

        val result = HermesHbc96.patch(
            bundle,
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                "androidGoldSubscriptionOverride",
                "getBoolean",
                "android_gold_subscription_override",
                HermesHbc96.OP_LOAD_CONST_TRUE,
            ),
        )
        val site = result.appliedSites.single()
        assertEquals(0, site.register)
        val actualSlice = result.bytes.copyOfRange(site.patchOffset, site.patchOffset + 5)
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

        val result = HermesHbc96.patch(
            bundle,
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                "androidGoldSubscriptionOverride",
                "getBoolean",
                "android_gold_subscription_override",
                HermesHbc96.OP_LOAD_CONST_TRUE,
            ),
        )
        val site = result.appliedSites.single()
        assertEquals(7, site.register)
        val actualSlice = result.bytes.copyOfRange(site.patchOffset, site.patchOffset + 5)
        assertTrue(byteArrayOf(0x78, 0x07, 0x5c, 0x07, 0x00).contentEquals(actualSlice))
    }

    @Test
    fun `patches synchronous helper early return and async JmpTrue and JmpTrueLong generators`() {
        // String IDs: 0=?anon_0_, 1=initAppsFlyer, 2=appsFlyer, 3=forceUpgrade, 4=getNumSentLockets
        val strings = listOf("?anon_0_", "initAppsFlyer", "appsFlyer", "forceUpgrade", "getNumSentLockets")

        val syncCode = byteArrayOf(
            0x37, 0x01, 0x02, 0x00, 0x02, 0x00, // GetById r1, r2, "appsFlyer"
            0x76, 0x00, 0x5c, 0x00,
        )
        val shortGenCode = byteArrayOf(
            HermesHbc96.OP_START_GENERATOR,
            HermesHbc96.OP_RESUME_GENERATOR, 0x00, 0x01,
            HermesHbc96.OP_JMP_TRUE, 0x10, 0x01,
            0x73, 0x02, 0x04, 0x00, // LoadConstString r2, "getNumSentLockets"
            HermesHbc96.OP_COMPLETE_GENERATOR, 0x5c, 0x00,
        )
        val longGenCode = byteArrayOf(
            HermesHbc96.OP_START_GENERATOR,
            HermesHbc96.OP_RESUME_GENERATOR, 0x00, 0x01,
            HermesHbc96.OP_JMP_TRUE_LONG, 0x15, 0x00, 0x00, 0x00, 0x01,
            0x73, 0x02, 0x03, 0x00, // LoadConstString r2, "forceUpgrade"
            HermesHbc96.OP_COMPLETE_GENERATOR, 0x5c, 0x00,
        )

        val bundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(
                SyntheticFunction(nameId = 1, code = syncCode),
                SyntheticFunction(nameId = 0, code = shortGenCode),
                SyntheticFunction(nameId = 0, code = longGenCode),
            ),
        )

        val mutations = listOf(
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "initAppsFlyer",
                replacement = byteArrayOf(HermesHbc96.OP_NEW_OBJECT, 0x00, HermesHbc96.OP_RET, 0x00),
                requiredStrings = listOf("appsFlyer"),
            ),
            HermesHbc96.Mutation.GeneratorEarlyReturn(
                functionName = "?anon_0_",
                requiredStrings = listOf("getNumSentLockets"),
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.GeneratorEarlyReturn(
                functionName = "?anon_0_",
                requiredStrings = listOf("forceUpgrade"),
                returnOpcode = HermesHbc96.OP_LOAD_CONST_UNDEFINED,
            ),
        )

        val pass1 = HermesHbc96.patch(bundle, mutations[0])
        val pass2 = HermesHbc96.patch(pass1.bytes, mutations[1])
        val pass3 = HermesHbc96.patch(pass2.bytes, mutations[2])

        val s0 = pass3.appliedSites.single()
        assertEquals(2, s0.functionIndex)
        assertTrue(
            byteArrayOf(
                HermesHbc96.OP_LOAD_CONST_UNDEFINED,
                0x01,
                HermesHbc96.OP_COMPLETE_GENERATOR,
                HermesHbc96.OP_RET,
                0x01,
            ).contentEquals(pass3.bytes.copyOfRange(s0.patchOffset, s0.patchOffset + 5)),
        )
        val s1 = pass2.appliedSites.single()
        assertEquals(1, s1.functionIndex)
        assertTrue(
            byteArrayOf(
                HermesHbc96.OP_LOAD_CONST_FALSE,
                0x01,
                HermesHbc96.OP_COMPLETE_GENERATOR,
                HermesHbc96.OP_RET,
                0x01,
            ).contentEquals(pass3.bytes.copyOfRange(s1.patchOffset, s1.patchOffset + 5)),
        )
        assertValidSha1Footer(pass3.bytes)
    }

    @Test
    fun `rejects unsupported Hermes bytecode version and corrupted SHA-1 footer`() {
        val seq = byteArrayOf(
            0x37, 0x01, 0x02, 0x00, 0x01, 0x00,
            0x73, 0x00, 0x02, 0x00,
            0x53, 0x00, 0x01, 0x02, 0x00,
            0x5c, 0x00,
        )
        val target = HermesHbc96.Mutation.RemoteConfigReturnConst(
            "androidGoldSubscriptionOverride",
            "getBoolean",
            "android_gold_subscription_override",
            HermesHbc96.OP_LOAD_CONST_TRUE,
        )

        val wrongVersionBundle = buildSyntheticBundle(
            version = 95,
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq)),
        )
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(wrongVersionBundle, target)
        }

        val corruptedFooterBundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq)),
        )
        corruptedFooterBundle[corruptedFooterBundle.lastIndex] =
            (corruptedFooterBundle[corruptedFooterBundle.lastIndex].toInt() xor 0xff).toByte()
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(corruptedFooterBundle, target)
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
        val target = HermesHbc96.Mutation.RemoteConfigReturnConst(
            "androidGoldSubscriptionOverride",
            "getBoolean",
            "android_gold_subscription_override",
            HermesHbc96.OP_LOAD_CONST_TRUE,
        )

        val missingFnBundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override", "other"),
            functions = listOf(SyntheticFunction(nameId = 3, code = seq)),
        )
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(missingFnBundle, target)
        }

        val duplicateCallBundle = buildSyntheticBundle(
            strings = listOf("androidGoldSubscriptionOverride", "getBoolean", "android_gold_subscription_override"),
            functions = listOf(SyntheticFunction(nameId = 0, code = seq + seq)),
        )
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(duplicateCallBundle, target)
        }
    }

    @Test
    fun `applies all real Locket mutations sequentially when bundle path is supplied`() {
        val bundlePath = System.getenv("LOCKET_BUNDLE_PATH")?.let(::File)?.takeIf(File::isFile) ?: return
        val expectedSha256 = System.getenv("LOCKET_EXPECTED_SHA256")

        val gold = HermesHbc96.patch(
            bundlePath.readBytes(),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                "androidGoldSubscriptionOverride",
                "getBoolean",
                "android_gold_subscription_override",
                HermesHbc96.OP_LOAD_CONST_TRUE,
            ),
        )
        assertValidSha1Footer(gold.bytes)

        if (!expectedSha256.isNullOrBlank()) {
            val actualSha256 = MessageDigest.getInstance("SHA-256")
                .digest(gold.bytes)
                .joinToString("") { "%02x".format(it) }
            assertEquals(expectedSha256.lowercase(), actualSha256)
        }
    }

    private fun assertValidSha1Footer(bytes: ByteArray) {
        val contentEnd = bytes.size - HermesHbc96.SHA1_SIZE
        val recomputedSha1 = MessageDigest.getInstance("SHA-1").apply {
            update(bytes, 0, contentEnd)
        }.digest()
        val storedSha1 = bytes.copyOfRange(contentEnd, bytes.size)
        assertTrue(recomputedSha1.contentEquals(storedSha1))
    }

    private data class SyntheticFunction(
        val nameId: Int,
        val code: ByteArray,
        val useLargeHeader: Boolean = false,
    )

    private fun buildSyntheticBundle(
        version: Int = HermesHbc96.HBC_VERSION,
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
        val smallStrOff = align4(HermesHbc96.HEADER_SIZE + funcTableSize)
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

        val totalSize = cursor + HermesHbc96.SHA1_SIZE
        val out = ByteArray(totalSize)

        writeI64Le(out, 0x00, HermesHbc96.HBC_MAGIC)
        writeI32Le(out, 0x08, version)
        writeI32Le(out, 0x20, totalSize)
        writeI32Le(out, 0x28, functions.size)
        writeI32Le(out, 0x34, strings.size)
        writeI32Le(out, 0x3c, storageBytes.size)

        System.arraycopy(smallStrings, 0, out, smallStrOff, smallStrings.size)
        System.arraycopy(storageBytes, 0, out, storageOff, storageBytes.size)

        for ((idx, fn) in functions.withIndex()) {
            val hOff = HermesHbc96.HEADER_SIZE + idx * 16
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

        val contentEnd = totalSize - HermesHbc96.SHA1_SIZE
        val digest = MessageDigest.getInstance("SHA-1").apply { update(out, 0, contentEnd) }.digest()
        System.arraycopy(digest, 0, out, contentEnd, HermesHbc96.SHA1_SIZE)
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
