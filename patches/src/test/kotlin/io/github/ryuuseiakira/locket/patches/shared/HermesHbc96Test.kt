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

        val zoom = HermesHbc96.Mutation.ImprovePinchZoomWorklet("HomeCameraTsx3Factory", "HomeCameraTsx3")
        val tele = HermesHbc96.Mutation.EnableTelephotoZoomToggle()
        val rawBundle = bundlePath.readBytes()
        for (combo in listOf(listOf(zoom, tele), listOf(tele, zoom))) {
            val res = HermesHbc96.patch(rawBundle, combo)
            assertValidSha1Footer(res.bytes)
            assertEquals(combo.size, res.appliedSites.size)
        }
    }

    @Test
    fun `rewrites pinch worklet bytecode from factory closure slot mapping and patches factory initData`() {
        val strings = listOf(
            "HomeCameraTsx3Factory",
            "HomeCameraTsx3",
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
            "Math",
            "zoom",
            "set",
            "min",
            "max",
            "maxZoom",
            "minZoom",
            "pinchStartZoom",
            "value",
            "pow",
            "event",
            "scale",
        )
        val sid = { name: String -> strings.indexOf(name) }

        val factoryAsm = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_CREATE_ENVIRONMENT, 0)
            op(HermesHbc96Asm.OP_LOAD_PARAM, 2, 1)
            getById(6, 2, 1, sid("zoom"))
            storeToEnvironment(0, 3, 6)
            getById(5, 2, 2, sid("minZoom"))
            storeToEnvironment(0, 4, 5)
            getById(4, 2, 3, sid("pinchStartZoom"))
            storeToEnvironment(0, 5, 4)
            getById(3, 2, 4, sid("maxZoom"))
            storeToEnvironment(0, 6, 3)
            op(HermesHbc96Asm.OP_CREATE_CLOSURE, 0, 0, 1, 0) // func #1 = HomeCameraTsx3
            op(HermesHbc96.OP_NEW_OBJECT, 1)
            putNewOwnById(1, 2, sid("code"))
            op(
                HermesHbc96Asm.OP_PUT_BY_ID,
                0,
                1,
                1,
                sid("__initData") and 0xff,
                (sid("__initData") ushr 8) and 0xff,
            )
            op(HermesHbc96.OP_RET, 0)
        }.build()

        // Intentionally tiny original worklet (4 bytes) to exercise relocation + DebugInfo shift!
        val tinyWorklet = byteArrayOf(HermesHbc96.OP_LOAD_CONST_UNDEFINED, 0x00, HermesHbc96.OP_RET, 0x00)

        val bundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(
                SyntheticFunction(nameId = sid("HomeCameraTsx3Factory"), code = factoryAsm, paramCount = 2, frameSize = 8, readCacheCount = 4),
                SyntheticFunction(nameId = sid("HomeCameraTsx3"), code = tinyWorklet, paramCount = 2, frameSize = 8),
            ),
            includeDebugTrailer = true,
        )
        val origDbgOff = readI32Le(bundle, 0x68)
        assertTrue(origDbgOff > 0)

        val mutation = HermesHbc96.Mutation.ImprovePinchZoomWorklet("HomeCameraTsx3Factory", "HomeCameraTsx3")
        val res = HermesHbc96.patch(bundle, mutation)
        assertTrue(res.bytes.size > bundle.size)
        val newDbgOff = readI32Le(res.bytes, 0x68)
        assertTrue(newDbgOff > origDbgOff)
        assertEquals(0, newDbgOff and 3)
        assertEquals(res.bytes.size, readI32Le(res.bytes, 0x20))
        assertValidSha1Footer(res.bytes)

        // Both factory (#0) and worklet (#1) should relocate before DebugInfo and decode cleanly.
        for (idx in 0..1) {
            val hOff = HermesHbc96.HEADER_SIZE + idx * 16
            val newOff = readI32Le(res.bytes, hOff) and 0x1ffffff
            val newSz = readI32Le(res.bytes, hOff + 4) and 0x7fff
            assertTrue(newOff >= origDbgOff && newOff + newSz <= newDbgOff)
            assertTrue(HermesHbc96Asm.decodeFunction(res.bytes, newOff, newOff + newSz).isNotEmpty())
        }

        // Factory (#0) and Worklet (#1) frame/cache minimums reserve local registers + outgoing call slots.
        val h0 = HermesHbc96.HEADER_SIZE
        val f0Frame = (readI32Le(res.bytes, h0 + 8) ushr 25) and 0x7f
        assertTrue(f0Frame >= 23, "Expected factory frameSize >= 23, got $f0Frame")

        val h1 = HermesHbc96.HEADER_SIZE + 16
        val w2 = readI32Le(res.bytes, h1 + 8)
        val w3 = readI32Le(res.bytes, h1 + 12)
        val f1Frame = (w2 ushr 25) and 0x7f
        assertTrue(f1Frame >= 18, "Expected worklet frameSize >= 18, got $f1Frame")
        assertTrue(((w3 ushr 8) and 0xff) >= 5)

        // Applying a second time fails cleanly once factory references synthesized initData helpers.
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(res.bytes, mutation)
        }
    }

    @Test
    fun `enables telephoto zoom toggle cleanly across synthetic Home, button, onPress, and getNextZoomValue`() {
        val strings = listOf(
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
            "c",
            "set",
            "value",
            "",
            "overlayZoomButtonProps",
        )
        val sid = { name: String -> strings.indexOf(name) }

        // fn #0: getNextZoomValue (paramCount = 4)
        val nextZoomCode = byteArrayOf(
            HermesHbc96Asm.OP_LOAD_PARAM, 0, 1,
            HermesHbc96Asm.OP_LOAD_PARAM, 2, 2,
            HermesHbc96Asm.OP_LOAD_PARAM, 1, 3,
            HermesHbc96.OP_RET, 0,
        )

        // fn #1: onPress t1 (env0 -> slot 0/1/2/..., calls Call4 on fn #0)
        val t1Code = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 0, 0)
            loadFromEnvironment(8, 0, 0)
            loadFromEnvironment(7, 0, 1)
            loadFromEnvironment(4, 0, 0)
            loadFromEnvironment(1, 0, 2)
            op(HermesHbc96.OP_LOAD_CONST_UNDEFINED, 0)
            op(HermesHbc96Asm.OP_CALL4, 4, 8, 0, 7, 4, 1)
            op(HermesHbc96.OP_RET, 0)
        }.build()

        // fn #2: CameraOverlayZoomButton render fn (empty name, paramCount = 2)
        val buttonCode = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_CREATE_ENVIRONMENT, 0)
            op(HermesHbc96Asm.OP_LOAD_PARAM, 2, 1)
            op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 1, 0)
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 3, 12) // c(12)
            op(HermesHbc96.OP_NEW_OBJECT, 3)
            getById(4, 2, 2, sid("zoom"))
            storeToEnvironment(0, 0, 4)
            getById(9, 2, 3, sid("neutralZoom"))
            storeToEnvironment(0, 1, 9)
            getById(12, 2, 4, sid("minZoom"))
            storeToEnvironment(0, 2, 12)
            // Use 6-byte GetById form (matching string IDs >= 256 in real bundles) for JmpLong splice headroom.
            op(
                HermesHbc96Asm.OP_GET_BY_ID,
                10,
                2,
                5,
                sid("backFacing") and 0xff,
                (sid("backFacing") ushr 8) and 0xff,
            )
            getById(14, 1, 11, sid("useDeviceOrientationRotationStyle"))
            getById(6, 1, 21, sid("CameraOverlayButton"))
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 5, 3)
            op(HermesHbc96Asm.OP_GET_BY_VAL, 5, 3, 5)
            op(HermesHbc96Asm.OP_JMP, 20)
            op(HermesHbc96Asm.OP_CREATE_CLOSURE, 0, 0, 1, 0)
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 2, 3)
            op(HermesHbc96Asm.OP_PUT_BY_VAL, 3, 2, 0)
            op(HermesHbc96Asm.OP_MOV, 5, 0)
            op(HermesHbc96.OP_RET, 5)
        }.build()
        val decodedBtn = HermesHbc96Asm.decodeFunction(buttonCode)
        val jmpPos = decodedBtn.first { it.opcode == HermesHbc96Asm.OP_JMP }.offset
        val closurePos = decodedBtn.first { it.opcode == HermesHbc96Asm.OP_CREATE_CLOSURE }.offset
        val retPos = decodedBtn.last().offset
        assertEquals(jmpPos + 2, closurePos)
        buttonCode[jmpPos + 1] = (retPos - jmpPos).toByte()

        // fn #3: Home
        val homeCode = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_LESS, 50, 59, 58)
            loadConstString(1, sid("camera_theme"))
            putNewOwnById(23, 83, sid("device"))
            putNewOwnById(23, 79, sid("zoomProps"))
            putNewOwnById(23, 55, sid("overlayZoomButtonProps"))
            putNewOwnById(55, 59, sid("minZoom"))
            putNewOwnById(55, 58, sid("neutralZoom"))
            putNewOwnById(55, 56, sid("zoom"))
            loadConstString(56, sid("back"))
            op(HermesHbc96Asm.OP_STRICT_EQ, 56, 57, 56)
            // Use 5-byte PutNewOwnById form for JmpLong splice headroom.
            op(
                HermesHbc96Asm.OP_PUT_NEW_OWN_BY_ID,
                55,
                56,
                sid("backFacing") and 0xff,
                (sid("backFacing") ushr 8) and 0xff,
            )
            op(HermesHbc96.OP_RET, 55)
        }.build()

        val bundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(
                SyntheticFunction(nameId = sid("getNextZoomValue"), code = nextZoomCode, paramCount = 4, frameSize = 4),
                SyntheticFunction(nameId = sid(""), code = t1Code, paramCount = 1, frameSize = 19),
                SyntheticFunction(nameId = sid(""), code = buttonCode, paramCount = 2, frameSize = 24, environmentSize = 3, readCacheCount = 21),
                SyntheticFunction(nameId = sid("Home"), code = homeCode, paramCount = 2, frameSize = 95, readCacheCount = 40),
            ),
            includeDebugTrailer = true,
        )

        val res = HermesHbc96.patch(
            bundle,
            HermesHbc96.Mutation.EnableTelephotoZoomToggle(zoomThreshold = 3.0, zoomTolerance = 0.05),
        )
        assertValidSha1Footer(res.bytes)
        assertEquals(res.bytes.size, readI32Le(res.bytes, 0x20))
        val newDbgOff = readI32Le(res.bytes, 0x68)
        assertTrue(newDbgOff > readI32Le(bundle, 0x68))
        assertEquals(0, newDbgOff and 3)

        for (idx in 0..3) {
            val hOff = HermesHbc96.HEADER_SIZE + idx * 16
            val off = readI32Le(res.bytes, hOff) and 0x1ffffff
            val sz = readI32Le(res.bytes, hOff + 4) and 0x7fff
            assertTrue(off + sz <= newDbgOff)
            assertTrue(HermesHbc96Asm.decodeFunction(res.bytes, off, off + sz).isNotEmpty())
        }
        assertEquals(5, (readI32Le(res.bytes, HermesHbc96.HEADER_SIZE) ushr 25) and 0x7f)
        val btnW3 = readI32Le(res.bytes, HermesHbc96.HEADER_SIZE + 2 * 16 + 12)
        assertEquals(4, btnW3 and 0xff)
        assertEquals(22, (btnW3 ushr 8) and 0xff)
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(res.bytes, HermesHbc96.Mutation.EnableTelephotoZoomToggle())
        }
    }

    @Test
    fun `composes ImprovePinchZoomWorklet and EnableTelephotoZoomToggle in either order cleanly`() {
        val strings = listOf(
            "HomeCameraTsx3Factory",
            "HomeCameraTsx3",
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
            "Math",
            "pow",
            "min",
            "max",
            "pinchStartZoom",
            "event",
            "scale",
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
            "photo",
            "type",
            "physicalDevices",
            "Array",
            "isArray",
            "length",
            "CameraOverlayButton",
            "useDeviceOrientationRotationStyle",
            "c",
            "set",
            "value",
            "",
            "overlayZoomButtonProps",
        )
        val sid = { name: String -> strings.indexOf(name) }

        val factoryAsm = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_CREATE_ENVIRONMENT, 0)
            op(HermesHbc96Asm.OP_LOAD_PARAM, 2, 1)
            getById(6, 2, 1, sid("zoom"))
            storeToEnvironment(0, 3, 6)
            getById(5, 2, 2, sid("minZoom"))
            storeToEnvironment(0, 4, 5)
            getById(4, 2, 3, sid("pinchStartZoom"))
            storeToEnvironment(0, 5, 4)
            getById(3, 2, 4, sid("maxZoom"))
            storeToEnvironment(0, 6, 3)
            op(HermesHbc96Asm.OP_CREATE_CLOSURE, 0, 0, 1, 0)
            op(HermesHbc96.OP_NEW_OBJECT, 1)
            putNewOwnById(1, 2, sid("code"))
            op(
                HermesHbc96Asm.OP_PUT_BY_ID,
                0,
                1,
                1,
                sid("__initData") and 0xff,
                (sid("__initData") ushr 8) and 0xff,
            )
            op(HermesHbc96.OP_RET, 0)
        }.build()
        val tinyWorklet = byteArrayOf(HermesHbc96.OP_LOAD_CONST_UNDEFINED, 0x00, HermesHbc96.OP_RET, 0x00)
        val nextZoomCode = byteArrayOf(
            HermesHbc96Asm.OP_LOAD_PARAM, 0, 1,
            HermesHbc96Asm.OP_LOAD_PARAM, 2, 2,
            HermesHbc96Asm.OP_LOAD_PARAM, 1, 3,
            HermesHbc96.OP_RET, 0,
        )
        val t1Code = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 0, 0)
            loadFromEnvironment(8, 0, 0)
            loadFromEnvironment(7, 0, 1)
            loadFromEnvironment(4, 0, 0)
            loadFromEnvironment(1, 0, 2)
            op(HermesHbc96.OP_LOAD_CONST_UNDEFINED, 0)
            op(HermesHbc96Asm.OP_CALL4, 4, 8, 0, 7, 4, 1)
            op(HermesHbc96.OP_RET, 0)
        }.build()
        val buttonCode = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_CREATE_ENVIRONMENT, 0)
            op(HermesHbc96Asm.OP_LOAD_PARAM, 2, 1)
            op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 1, 0)
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 3, 12)
            op(HermesHbc96.OP_NEW_OBJECT, 3)
            getById(4, 2, 2, sid("zoom"))
            storeToEnvironment(0, 0, 4)
            getById(9, 2, 3, sid("neutralZoom"))
            storeToEnvironment(0, 1, 9)
            getById(12, 2, 4, sid("minZoom"))
            storeToEnvironment(0, 2, 12)
            op(
                HermesHbc96Asm.OP_GET_BY_ID,
                10,
                2,
                5,
                sid("backFacing") and 0xff,
                (sid("backFacing") ushr 8) and 0xff,
            )
            getById(14, 1, 11, sid("useDeviceOrientationRotationStyle"))
            getById(6, 1, 21, sid("CameraOverlayButton"))
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 5, 3)
            op(HermesHbc96Asm.OP_GET_BY_VAL, 5, 3, 5)
            op(HermesHbc96Asm.OP_JMP, 20)
            op(HermesHbc96Asm.OP_CREATE_CLOSURE, 0, 0, 3, 0) // func #3 = t1
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 2, 3)
            op(HermesHbc96Asm.OP_PUT_BY_VAL, 3, 2, 0)
            op(HermesHbc96Asm.OP_MOV, 5, 0)
            op(HermesHbc96.OP_RET, 5)
        }.build()
        val decodedBtn = HermesHbc96Asm.decodeFunction(buttonCode)
        val jmpPos = decodedBtn.first { it.opcode == HermesHbc96Asm.OP_JMP }.offset
        buttonCode[jmpPos + 1] = (decodedBtn.last().offset - jmpPos).toByte()
        val homeCode = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_LESS, 50, 59, 58)
            loadConstString(1, sid("camera_theme"))
            putNewOwnById(23, 83, sid("device"))
            putNewOwnById(23, 79, sid("zoomProps"))
            putNewOwnById(23, 55, sid("overlayZoomButtonProps"))
            putNewOwnById(55, 59, sid("minZoom"))
            putNewOwnById(55, 58, sid("neutralZoom"))
            putNewOwnById(55, 56, sid("zoom"))
            loadConstString(56, sid("back"))
            op(HermesHbc96Asm.OP_STRICT_EQ, 56, 57, 56)
            op(
                HermesHbc96Asm.OP_PUT_NEW_OWN_BY_ID,
                55,
                56,
                sid("backFacing") and 0xff,
                (sid("backFacing") ushr 8) and 0xff,
            )
            op(HermesHbc96.OP_RET, 55)
        }.build()

        val bundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(
                SyntheticFunction(nameId = sid("HomeCameraTsx3Factory"), code = factoryAsm, paramCount = 2, frameSize = 8, readCacheCount = 4),
                SyntheticFunction(nameId = sid("HomeCameraTsx3"), code = tinyWorklet, paramCount = 2, frameSize = 8),
                SyntheticFunction(nameId = sid("getNextZoomValue"), code = nextZoomCode, paramCount = 4, frameSize = 4),
                SyntheticFunction(nameId = sid(""), code = t1Code, paramCount = 1, frameSize = 19),
                SyntheticFunction(nameId = sid(""), code = buttonCode, paramCount = 2, frameSize = 24, environmentSize = 3, readCacheCount = 21),
                SyntheticFunction(nameId = sid("Home"), code = homeCode, paramCount = 2, frameSize = 95, readCacheCount = 40),
            ),
            includeDebugTrailer = true,
        )

        val zoom = HermesHbc96.Mutation.ImprovePinchZoomWorklet("HomeCameraTsx3Factory", "HomeCameraTsx3")
        val tele = HermesHbc96.Mutation.EnableTelephotoZoomToggle()
        val fwd = HermesHbc96.patch(bundle, listOf(zoom, tele))
        val rev = HermesHbc96.patch(bundle, listOf(tele, zoom))

        for (res in listOf(fwd, rev)) {
            assertValidSha1Footer(res.bytes)
            assertEquals(res.bytes.size, readI32Le(res.bytes, 0x20))
            val newDbgOff = readI32Le(res.bytes, 0x68)
            assertEquals(0, newDbgOff and 3)
            for (idx in 0..5) {
                val hOff = HermesHbc96.HEADER_SIZE + idx * 16
                val off = readI32Le(res.bytes, hOff) and 0x1ffffff
                val sz = readI32Le(res.bytes, hOff + 4) and 0x7fff
                assertTrue(off + sz <= newDbgOff)
                assertTrue(HermesHbc96Asm.decodeFunction(res.bytes, off, off + sz).isNotEmpty())
            }
        }
    }

    @Test
    fun `reserves outgoing call slots and overflows Home into LargeFuncHeader cleanly`() {
        val strings = listOf(
            "Home",
            "getNextZoomValue",
            "androidGoldSubscriptionOverride",
            "getBoolean",
            "android_gold_subscription_override",
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
            "useDeviceOrientationRotationStyle",
            "CameraOverlayButton",
            "",
            "overlayZoomButtonProps",
        )
        val sid = { name: String -> strings.indexOf(name) }

        val nextZoomCode = byteArrayOf(
            HermesHbc96Asm.OP_LOAD_PARAM, 0, 1,
            HermesHbc96Asm.OP_LOAD_PARAM, 2, 2,
            HermesHbc96Asm.OP_LOAD_PARAM, 1, 3,
            HermesHbc96.OP_RET, 0,
        )
        val t1Code = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 0, 0)
            loadFromEnvironment(8, 0, 0)
            loadFromEnvironment(7, 0, 1)
            loadFromEnvironment(4, 0, 0)
            loadFromEnvironment(1, 0, 2)
            op(HermesHbc96.OP_LOAD_CONST_UNDEFINED, 0)
            op(HermesHbc96Asm.OP_CALL4, 4, 8, 0, 7, 4, 1)
            op(HermesHbc96.OP_RET, 0)
        }.build()
        val buttonCode = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_CREATE_ENVIRONMENT, 0)
            op(HermesHbc96Asm.OP_LOAD_PARAM, 2, 1)
            op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 1, 0)
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 3, 12)
            op(HermesHbc96.OP_NEW_OBJECT, 3)
            getById(4, 2, 2, sid("zoom"))
            storeToEnvironment(0, 0, 4)
            getById(9, 2, 3, sid("neutralZoom"))
            storeToEnvironment(0, 1, 9)
            getById(12, 2, 4, sid("minZoom"))
            storeToEnvironment(0, 2, 12)
            op(
                HermesHbc96Asm.OP_GET_BY_ID,
                10,
                2,
                5,
                sid("backFacing") and 0xff,
                (sid("backFacing") ushr 8) and 0xff,
            )
            getById(14, 1, 11, sid("useDeviceOrientationRotationStyle"))
            getById(6, 1, 21, sid("CameraOverlayButton"))
            op(HermesHbc96Asm.OP_MOV, 19, 14)
            op(HermesHbc96Asm.OP_CALL3, 5, 14, 1, 2, 3)
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 5, 3)
            op(HermesHbc96Asm.OP_GET_BY_VAL, 5, 3, 5)
            op(HermesHbc96Asm.OP_JMP, 20)
            op(HermesHbc96Asm.OP_CREATE_CLOSURE, 0, 0, 1, 0) // func #1 = t1
            op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 2, 3)
            op(HermesHbc96Asm.OP_PUT_BY_VAL, 3, 2, 0)
            op(HermesHbc96Asm.OP_MOV, 5, 0)
            op(HermesHbc96.OP_RET, 5)
        }.build()
        val decodedBtn = HermesHbc96Asm.decodeFunction(buttonCode)
        val jmpPos = decodedBtn.first { it.opcode == HermesHbc96Asm.OP_JMP }.offset
        buttonCode[jmpPos + 1] = (decodedBtn.last().offset - jmpPos).toByte()

        val homeCode = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_MOV, 115, 59)
            op(HermesHbc96Asm.OP_CALL3, 50, 51, 52, 53, 54)
            op(HermesHbc96Asm.OP_LESS, 50, 59, 58)
            loadConstString(1, sid("camera_theme"))
            putNewOwnById(23, 83, sid("device"))
            putNewOwnById(23, 79, sid("zoomProps"))
            putNewOwnById(23, 55, sid("overlayZoomButtonProps"))
            putNewOwnById(55, 59, sid("minZoom"))
            putNewOwnById(55, 58, sid("neutralZoom"))
            putNewOwnById(55, 56, sid("zoom"))
            loadConstString(56, sid("back"))
            op(HermesHbc96Asm.OP_STRICT_EQ, 56, 57, 56)
            op(
                HermesHbc96Asm.OP_PUT_NEW_OWN_BY_ID,
                55,
                56,
                sid("backFacing") and 0xff,
                (sid("backFacing") ushr 8) and 0xff,
            )
            op(HermesHbc96.OP_RET, 55)
        }.build()

        val remoteCode = byteArrayOf(
            0x37, 0x01, 0x02, 0x00, sid("getBoolean").toByte(), 0x00,
            0x73, 0x00, sid("android_gold_subscription_override").toByte(), 0x00,
            0x53, 0x00, 0x01, 0x02, 0x00,
            0x5c, 0x00,
        )

        val bundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(
                SyntheticFunction(nameId = sid("getNextZoomValue"), code = nextZoomCode, paramCount = 4, frameSize = 4),
                SyntheticFunction(nameId = sid(""), code = t1Code, paramCount = 1, frameSize = 19),
                SyntheticFunction(nameId = sid(""), code = buttonCode, paramCount = 2, frameSize = 29, environmentSize = 3, readCacheCount = 21),
                SyntheticFunction(nameId = sid("Home"), code = homeCode, paramCount = 2, frameSize = 125, readCacheCount = 40),
                SyntheticFunction(nameId = sid("androidGoldSubscriptionOverride"), code = remoteCode, paramCount = 1, frameSize = 16),
            ),
            includeDebugTrailer = true,
        )
        val origDbgOff = readI32Le(bundle, 0x68)

        val res = HermesHbc96.patch(bundle, HermesHbc96.Mutation.EnableTelephotoZoomToggle())
        assertValidSha1Footer(res.bytes)
        val newDbgOff = readI32Le(res.bytes, 0x68)
        assertTrue(newDbgOff > origDbgOff)
        assertEquals(0, newDbgOff and 3)

        // t1 (#1): maxReg=8 + 1 + Call(argc=5 -> 11) = 20
        val h1 = HermesHbc96.HEADER_SIZE + 1 * 16
        assertEquals(20, (readI32Le(res.bytes, h1 + 8) ushr 25) and 0x7f)

        // CameraOverlayZoomButton (#2): maxReg=19 -> scratchReg=20 + 1 + Call3(9) = 30
        val h2 = HermesHbc96.HEADER_SIZE + 2 * 16
        assertEquals(30, (readI32Le(res.bytes, h2 + 8) ushr 25) and 0x7f)

        // Home (#3): s5=122 + 1 + Call3(9) = 132 >= 128 -> must overflow to a 4-byte-aligned LargeFuncHeader!
        val h3 = HermesHbc96.HEADER_SIZE + 3 * 16
        val w0 = readI32Le(res.bytes, h3)
        val w2 = readI32Le(res.bytes, h3 + 8)
        val w3 = readI32Le(res.bytes, h3 + 12)
        assertTrue(((w3 ushr 29) and 1) != 0, "Expected Home to set overflowed flag")
        val largeOff = ((w2 and 0xffff) shl 16) or (w0 and 0xffff)
        assertEquals(0, largeOff and 3)
        assertTrue(largeOff in origDbgOff until newDbgOff)
        val homeCodeOff = readI32Le(res.bytes, largeOff)
        val homeCodeSz = readI32Le(res.bytes, largeOff + 8)
        val homeFrameSz = readI32Le(res.bytes, largeOff + 20)
        assertEquals(132, homeFrameSz)
        assertTrue(homeCodeOff >= origDbgOff && homeCodeOff + homeCodeSz <= newDbgOff)
        assertTrue(HermesHbc96Asm.decodeFunction(res.bytes, homeCodeOff, homeCodeOff + homeCodeSz).isNotEmpty())

        // Applying a subsequent patch pass must read Home's LargeFuncHeader cleanly without losing it.
        val pass2 = HermesHbc96.patch(
            res.bytes,
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                "androidGoldSubscriptionOverride",
                "getBoolean",
                "android_gold_subscription_override",
                HermesHbc96.OP_LOAD_CONST_TRUE,
            ),
        )
        assertValidSha1Footer(pass2.bytes)
        val pass2W0 = readI32Le(pass2.bytes, h3)
        val pass2W2 = readI32Le(pass2.bytes, h3 + 8)
        val pass2LargeOff = ((pass2W2 and 0xffff) shl 16) or (pass2W0 and 0xffff)
        assertEquals(132, readI32Le(pass2.bytes, pass2LargeOff + 20))

        // Reject expanding frameSize when a spliced function contains a stack-top-relative Call.
        val stackRelButton = HermesHbc96Asm.Builder(0).apply {
            op(HermesHbc96Asm.OP_CALL, 5, 14, 2)
            raw(buttonCode)
        }.build()
        val stackRelBundle = buildSyntheticBundle(
            strings = strings,
            functions = listOf(
                SyntheticFunction(nameId = sid("getNextZoomValue"), code = nextZoomCode, paramCount = 4, frameSize = 4),
                SyntheticFunction(nameId = sid(""), code = t1Code, paramCount = 1, frameSize = 19),
                SyntheticFunction(nameId = sid(""), code = stackRelButton, paramCount = 2, frameSize = 29, environmentSize = 3, readCacheCount = 21),
                SyntheticFunction(nameId = sid("Home"), code = homeCode, paramCount = 2, frameSize = 125, readCacheCount = 40),
            ),
            includeDebugTrailer = true,
        )
        assertFailsWith<IllegalArgumentException> {
            HermesHbc96.patch(stackRelBundle, HermesHbc96.Mutation.EnableTelephotoZoomToggle())
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
        val paramCount: Int = 2,
        val frameSize: Int = 16,
        val environmentSize: Int = 0,
        val readCacheCount: Int = 0,
    )

    private fun buildSyntheticBundle(
        version: Int = HermesHbc96.HBC_VERSION,
        strings: List<String>,
        functions: List<SyntheticFunction>,
        includeDebugTrailer: Boolean = false,
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

        val dbgOff = if (includeDebugTrailer) align4(cursor) else 0
        val totalSize = (if (includeDebugTrailer) dbgOff + 28 else cursor) + HermesHbc96.SHA1_SIZE
        val out = ByteArray(totalSize)

        writeI64Le(out, 0x00, HermesHbc96.HBC_MAGIC)
        writeI32Le(out, 0x08, version)
        writeI32Le(out, 0x20, totalSize)
        writeI32Le(out, 0x28, functions.size)
        writeI32Le(out, 0x34, strings.size)
        writeI32Le(out, 0x3c, storageBytes.size)
        if (includeDebugTrailer) {
            writeI32Le(out, 0x68, dbgOff)
        }

        System.arraycopy(smallStrings, 0, out, smallStrOff, smallStrings.size)
        System.arraycopy(storageBytes, 0, out, storageOff, storageBytes.size)

        for ((idx, fn) in functions.withIndex()) {
            val hOff = HermesHbc96.HEADER_SIZE + idx * 16
            if (!fn.useLargeHeader) {
                val w0 = (codeOffsets[idx] and 0x1ffffff) or ((fn.paramCount and 0x7f) shl 25)
                val w1 = (fn.code.size and 0x7fff) or ((fn.nameId and 0x1ffff) shl 15)
                val w2 = (fn.frameSize and 0x7f) shl 25
                val w3 = (fn.environmentSize and 0xff) or ((fn.readCacheCount and 0xff) shl 8) or (0x04 shl 24)
                writeI32Le(out, hOff, w0)
                writeI32Le(out, hOff + 4, w1)
                writeI32Le(out, hOff + 8, w2)
                writeI32Le(out, hOff + 12, w3)
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

    private fun readI32Le(buf: ByteArray, offset: Int): Int {
        return (buf[offset].toInt() and 0xff) or
            ((buf[offset + 1].toInt() and 0xff) shl 8) or
            ((buf[offset + 2].toInt() and 0xff) shl 16) or
            ((buf[offset + 3].toInt() and 0xff) shl 24)
    }

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
