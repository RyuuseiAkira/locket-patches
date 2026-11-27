// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96CameraMutations.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Camera zoom & telephoto HBC mutations

package io.github.ryuuseiakira.locket.patches.shared

/**
 * Semantic bytecode rewrites for Locket's Reanimated pinch-zoom worklet and camera lens-preset
 * cycling (`0.5x` / `1x` / `3x` telephoto).
 */
internal object HermesHbc96CameraMutations {
    fun applyImprovePinchZoomWorklet(
        ctx: HermesHbc96.PatchContext,
        mutation: HermesHbc96.Mutation.ImprovePinchZoomWorklet,
    ): HermesHbc96.AppliedSite {
        val factoryId = ctx.stringIds.getValue(mutation.factoryFunctionName)
        val workletNameId = ctx.stringIds.getValue(mutation.workletFunctionName)
        val scaleStrId = ctx.stringIds.getValue("scale")
        val mathStrId = ctx.stringIds.getValue("Math")
        val powStrId = ctx.stringIds.getValue("pow")
        val valueStrId = ctx.stringIds.getValue("value")
        val setStrId = ctx.stringIds.getValue("set")
        val zoomStrId = ctx.stringIds.getValue("zoom")
        val minZoomStrId = ctx.stringIds.getValue("minZoom")
        val pinchStartZoomStrId = ctx.stringIds.getValue("pinchStartZoom")
        val maxZoomStrId = ctx.stringIds.getValue("maxZoom")

        val factories = ctx.functionsByNameId.getValue(factoryId)
        require(factories.size == 1) {
            "Expected 1 '${mutation.factoryFunctionName}' function, found ${factories.size}."
        }
        val factory = factories[0]
        val factoryCode = ctx.functionCode(factory)
        val factoryIns = HermesHbc96Asm.decodeFunction(factoryCode)

        val closureSlots = resolveFactoryCaptureSlots(
            code = factoryCode,
            instructions = factoryIns,
            targetStringIds = mapOf(
                zoomStrId to "zoom",
                minZoomStrId to "minZoom",
                pinchStartZoomStrId to "pinchStartZoom",
                maxZoomStrId to "maxZoom",
            ),
            expectedClosureNameId = workletNameId,
            ctx = ctx,
        )

        val worklet = ctx.allFunctions[closureSlots.closureFunctionId]
        require(worklet.nameId == workletNameId && !worklet.hasExceptionHandler && worklet.paramCount == 2) {
            "Resolved worklet #${worklet.index} does not match ${mutation.workletFunctionName} shape."
        }
        require(!ctx.functionContainsAllStrings(factory, listOf("indexOf", "slice"))) {
            "Worklet factory '${mutation.factoryFunctionName}' appears already patched."
        }

        patchPinchWorkletFactoryInitData(ctx, factory, mutation)

        val workletCode = ctx.functionCode(worklet)
        val workletIns = HermesHbc96Asm.decodeFunction(workletCode)
        val (maxReg, _) = HermesHbc96Asm.scanMaxRegisterAndReadCache(workletCode, workletIns)
        require(maxReg >= 0) { "Empty pinch worklet #${worklet.index}." }

        val asm = HermesHbc96Asm.Builder()
        asm.op(HermesHbc96Asm.OP_GET_ENVIRONMENT, 8, 0)
        asm.op(HermesHbc96Asm.OP_LOAD_PARAM, 0, 1)
        asm.getById(1, 0, 1, scaleStrId)
        asm.loadConstDouble(2, mutation.minScaleClamp)
        asm.jumpLong(HermesHbc96Asm.OP_J_LESS_LONG, "scale_ok", 2, 1)
        asm.op(HermesHbc96Asm.OP_MOV, 1, 2)
        asm.label("scale_ok")
        asm.op(HermesHbc96Asm.OP_GET_GLOBAL_OBJECT, 0)
        asm.tryGetById(3, 0, 2, mathStrId)
        asm.getById(4, 3, 3, powStrId)
        asm.loadConstDouble(5, mutation.exponent)
        asm.op(HermesHbc96Asm.OP_CALL3, 1, 4, 3, 1, 5)
        asm.loadFromEnvironment(2, 8, closureSlots.slots.getValue("pinchStartZoom"))
        asm.getById(2, 2, 4, valueStrId)
        asm.op(HermesHbc96Asm.OP_MUL, 1, 2, 1)
        asm.loadFromEnvironment(2, 8, closureSlots.slots.getValue("minZoom"))
        asm.jumpLong(HermesHbc96Asm.OP_J_LESS_LONG, "above_min", 2, 1)
        asm.op(HermesHbc96Asm.OP_MOV, 1, 2)
        asm.label("above_min")
        asm.loadFromEnvironment(2, 8, closureSlots.slots.getValue("maxZoom"))
        asm.jumpLong(HermesHbc96Asm.OP_J_LESS_LONG, "below_max", 1, 2)
        asm.op(HermesHbc96Asm.OP_MOV, 1, 2)
        asm.label("below_max")
        asm.loadFromEnvironment(3, 8, closureSlots.slots.getValue("zoom"))
        asm.getById(2, 3, 5, setStrId)
        asm.op(HermesHbc96Asm.OP_CALL2, 1, 2, 3, 1)
        asm.op(HermesHbc96.OP_LOAD_CONST_UNDEFINED, 0)
        asm.op(HermesHbc96.OP_RET, 0)

        val newCode = asm.build()
        val requiredFrame = maxOf(worklet.frameSize, 9)
        val requiredCache = maxOf(worklet.highestReadCacheIndex, 5)
        val updatedOffset = ctx.writeFunctionCode(
            fn = worklet,
            newCode = newCode,
            newFrameSize = requiredFrame,
            newReadCacheIndex = requiredCache,
        )

        return HermesHbc96.AppliedSite(
            label = mutation.label,
            functionIndex = worklet.index,
            patchOffset = updatedOffset,
            byteCount = newCode.size,
            register = 1,
        )
    }

    private fun patchPinchWorkletFactoryInitData(
        ctx: HermesHbc96.PatchContext,
        factory: HermesHbc96.FunctionMeta,
        mutation: HermesHbc96.Mutation.ImprovePinchZoomWorklet,
    ): Int {
        val code = ctx.functionCode(factory)
        val ins = HermesHbc96Asm.decodeFunction(code)
        val (maxReg, maxRCache) = HermesHbc96Asm.scanMaxRegisterAndReadCache(code, ins)

        val idInitData = ctx.stringIds.getValue("__initData")
        val idCode = ctx.stringIds.getValue("code")
        val idIndexOf = ctx.stringIds.getValue("indexOf")
        val idClosureKey = ctx.stringIds.getValue("__closure")
        val idSlice = ctx.stringIds.getValue("slice")
        val idDot = ctx.stringIds.getValue(".")
        val idLParen = ctx.stringIds.getValue("(")
        val idRParen = ctx.stringIds.getValue(")")
        val idComma = ctx.stringIds.getValue(",")
        val idMul = ctx.stringIds.getValue("*")
        val idSemi = ctx.stringIds.getValue(";")
        val idRBrace = ctx.stringIds.getValue("}")
        val idMath = ctx.stringIds.getValue("Math")
        val idZoom = ctx.stringIds.getValue("zoom")
        val idSet = ctx.stringIds.getValue("set")
        val idMin = ctx.stringIds.getValue("min")
        val idMax = ctx.stringIds.getValue("max")
        val idMaxZoom = ctx.stringIds.getValue("maxZoom")
        val idMinZoom = ctx.stringIds.getValue("minZoom")
        val idPinchStartZoom = ctx.stringIds.getValue("pinchStartZoom")
        val idValue = ctx.stringIds.getValue("value")
        val idPow = ctx.stringIds.getValue("pow")
        val idEvent = ctx.stringIds.getValue("event")
        val idScale = ctx.stringIds.getValue("scale")

        var putInitIdx = -1
        for (i in ins.indices) {
            val put = HermesHbc96Asm.readPutById(code, ins[i].offset)
            if (put != null && put.stringId == idInitData) {
                require(putInitIdx < 0) { "Ambiguous __initData assignment in ${mutation.factoryFunctionName}." }
                putInitIdx = i
            }
        }
        require(putInitIdx in 0 until ins.size - 1) {
            "Failed to locate __initData assignment in ${mutation.factoryFunctionName}."
        }

        val putInstr = ins[putInitIdx]
        val putAccess = HermesHbc96Asm.readPutById(code, putInstr.offset)!!
        require(putInstr.length >= 5) { "__initData assignment shorter than 5 bytes in #${factory.index}." }
        val rInitData = putAccess.regObj
        val resumeOff = ins[putInitIdx + 1].offset
        val origPutBytes = code.copyOfRange(putInstr.offset, resumeOff)

        val s0 = maxReg + 1
        val s1 = maxReg + 2
        val s2 = maxReg + 3
        val s3 = maxReg + 4
        val s4 = maxReg + 5
        val s5 = maxReg + 6
        val s6 = maxReg + 7
        val newFrameSize = maxOf(factory.frameSize, s6 + 1)
        val newRCache = maxRCache + 3
        require(newFrameSize < 128 && newRCache <= 0xff) {
            "Worklet factory register/cache budget exhausted (#${factory.index})."
        }

        val tailOff = code.size
        val b = HermesHbc96Asm.Builder(tailOff)
        b.getById(s0, rInitData, maxRCache + 1, idCode)
        b.jumpLong(HermesHbc96Asm.OP_JMP_FALSE_LONG, "keep_orig", s0)
        b.getById(s1, s0, maxRCache + 2, idIndexOf)
        b.loadConstString(s2, idClosureKey)
        b.op(HermesHbc96Asm.OP_CALL2, s1, s1, s0, s2)
        b.op(HermesHbc96.OP_LOAD_CONST_ZERO, s2)
        b.jumpLong(HermesHbc96Asm.OP_J_LESS_LONG, "keep_orig", s1, s2)
        b.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, s3, 10)
        b.op(HermesHbc96Asm.OP_ADD, s1, s1, s3)
        b.getById(s3, s0, maxRCache + 3, idSlice)
        b.op(HermesHbc96Asm.OP_CALL3, s0, s3, s0, s2, s1)

        // Reusable punctuation/namespace constants while appending body onto s0.
        b.loadConstString(s1, idDot)
        b.loadConstString(s2, idLParen)
        b.loadConstString(s3, idRParen)
        b.loadConstString(s4, idComma)
        b.loadConstString(s5, idMath)

        fun addId(id: Int) {
            b.loadConstString(s6, id)
            b.op(HermesHbc96Asm.OP_ADD, s0, s0, s6)
        }
        fun addReg(r: Int) {
            b.op(HermesHbc96Asm.OP_ADD, s0, s0, r)
        }
        fun addDouble(v: Double) {
            b.loadConstDouble(s6, v)
            b.op(HermesHbc96Asm.OP_ADD, s0, s0, s6)
        }

        addId(idZoom); addReg(s1); addId(idSet); addReg(s2)
        addReg(s5); addReg(s1); addId(idMin); addReg(s2); addId(idMaxZoom); addReg(s4)
        addReg(s5); addReg(s1); addId(idMax); addReg(s2); addId(idMinZoom); addReg(s4)
        addId(idPinchStartZoom); addReg(s1); addId(idValue); addId(idMul)
        addReg(s5); addReg(s1); addId(idPow); addReg(s2)
        addReg(s5); addReg(s1); addId(idMax); addReg(s2)
        addDouble(mutation.minScaleClamp); addReg(s4); addId(idEvent); addReg(s1); addId(idScale)
        addReg(s3); addReg(s4); addDouble(mutation.exponent)
        addReg(s3); addReg(s3); addReg(s3); addReg(s3); addId(idSemi); addId(idRBrace)

        b.op(HermesHbc96.OP_NEW_OBJECT, s6)
        b.putNewOwnById(s6, s0, idCode)
        b.op(HermesHbc96Asm.OP_MOV, rInitData, s6)
        b.label("keep_orig")
        b.raw(origPutBytes)
        b.jmpLongToOffset(resumeOff)

        val tailBytes = b.build()
        HermesHbc96Asm.overwriteWithJmpLongAndPad(
            code = code,
            patchOffset = putInstr.offset,
            replacedLength = resumeOff - putInstr.offset,
            targetOffset = tailOff,
        )
        return ctx.writeFunctionCode(
            fn = factory,
            newCode = code + tailBytes,
            newFrameSize = newFrameSize,
            newReadCacheIndex = newRCache,
        )
    }

    fun applyEnableTelephotoZoomToggle(
        ctx: HermesHbc96.PatchContext,
        mutation: HermesHbc96.Mutation.EnableTelephotoZoomToggle,
    ): HermesHbc96.AppliedSite {
        require(mutation.zoomThreshold in 1.1..255.0) {
            "Unsupported telephoto zoom threshold: ${mutation.zoomThreshold}."
        }
        require(mutation.zoomTolerance in 0.001..0.5) {
            "Unsupported zoom tolerance: ${mutation.zoomTolerance}."
        }

        val nextZoomFn = resolveUniqueFunction(ctx, "getNextZoomValue") { fn ->
            !fn.hasExceptionHandler && fn.paramCount == 4
        }
        val overlayButtonFn = findOverlayZoomButtonFunction(ctx)
        val homeFn = resolveUniqueFunction(ctx, "Home") { fn ->
            !fn.hasExceptionHandler &&
                ctx.functionContainsAllStrings(
                    fn,
                    listOf("overlayZoomButtonProps", "neutralZoom", "minZoom", "backFacing", "camera_theme"),
                )
        }

        val (t1FnId, lensSwitchEnvSlot) = patchOverlayZoomButton(ctx, overlayButtonFn)
        patchZoomButtonOnPress(
            ctx = ctx,
            t1Fn = ctx.allFunctions[t1FnId],
            lensSwitchEnvSlot = lensSwitchEnvSlot,
        )
        rewriteGetNextZoomValue(ctx, nextZoomFn, mutation.zoomThreshold, mutation.zoomTolerance)
        val homeOffset = patchHomeCameraZoomDetection(ctx, homeFn, mutation.zoomThreshold)

        return HermesHbc96.AppliedSite(
            label = mutation.label,
            functionIndex = homeFn.index,
            patchOffset = homeOffset,
            byteCount = homeFn.codeSize,
            register = 0,
        )
    }

    private data class FactoryCaptures(
        val closureFunctionId: Int,
        val slots: Map<String, Int>,
    )

    private fun resolveFactoryCaptureSlots(
        code: ByteArray,
        instructions: List<HermesHbc96Asm.DecodedInstruction>,
        targetStringIds: Map<Int, String>,
        expectedClosureNameId: Int,
        ctx: HermesHbc96.PatchContext,
    ): FactoryCaptures {
        val regToProp = LinkedHashMap<Int, String>()
        val slots = LinkedHashMap<String, Int>()
        var matchedClosureId = -1

        for (ins in instructions) {
            val idAccess = HermesHbc96Asm.readGetById(code, ins.offset)
            if (idAccess != null) {
                val propName = targetStringIds[idAccess.stringId]
                if (propName != null) {
                    regToProp[idAccess.regDst] = propName
                }
            }
            val store = HermesHbc96Asm.readStoreToEnvironment(code, ins.offset)
            if (store != null) {
                val prop = regToProp[store.regVal]
                if (prop != null) {
                    slots[prop] = store.envSlot
                }
            }
            val closure = HermesHbc96Asm.readCreateClosure(code, ins.offset)
            if (closure != null && ctx.allFunctions[closure.functionId].nameId == expectedClosureNameId) {
                matchedClosureId = closure.functionId
            }
        }

        require(matchedClosureId >= 0) { "Failed to locate worklet closure in factory." }
        for (name in targetStringIds.values) {
            require(name in slots) { "Missing closure capture '$name' in worklet factory." }
        }
        return FactoryCaptures(matchedClosureId, slots)
    }

    private fun findOverlayZoomButtonFunction(ctx: HermesHbc96.PatchContext): HermesHbc96.FunctionMeta {
        val req = listOf(
            "CameraOverlayButton",
            "backFacing",
            "useDeviceOrientationRotationStyle",
            "neutralZoom",
            "minZoom",
            "zoom",
        )
        val matches = ctx.allFunctions.filter { fn ->
            !fn.hasExceptionHandler &&
                fn.paramCount == 2 &&
                ctx.functionContainsAllStrings(fn, req)
        }
        require(matches.size == 1) {
            "Expected 1 CameraOverlayZoomButton render function, found ${matches.size}."
        }
        return matches[0]
    }

    private fun patchOverlayZoomButton(
        ctx: HermesHbc96.PatchContext,
        fn: HermesHbc96.FunctionMeta,
    ): Pair<Int, Int> {
        val backFacingId = ctx.stringIds.getValue("backFacing")
        val lensSwitchId = ctx.stringIds.getValue("lensSwitch")
        val code = ctx.functionCode(fn)
        val ins = HermesHbc96Asm.decodeFunction(code)
        val (maxReg, maxRCache) = HermesHbc96Asm.scanMaxRegisterAndReadCache(code, ins)

        val scratchReg = maxReg + 1
        val newRCache = maxRCache + 1
        val newEnvSlot = fn.environmentSize
        require(scratchReg < 128 && newRCache <= 0xff && newEnvSlot <= 0xff) {
            "CameraOverlayZoomButton register/cache/env budget exhausted."
        }

        var cacheInitIdx = -1
        var backFacingIdx = -1
        var createClosureIdx = -1
        var cacheReg = -1
        var closureReg = -1
        var envReg = -1
        var t1FnId = -1

        for (i in ins.indices) {
            val cur = ins[i]
            val off = cur.offset
            if (cacheInitIdx < 0 &&
                cur.opcode == HermesHbc96Asm.OP_LOAD_CONST_UINT8 &&
                (code[off + 2].toInt() and 0xff) == 12
            ) {
                cacheInitIdx = i
                cacheReg = code[off + 1].toInt() and 0xff
            }
            val getId = HermesHbc96Asm.readGetById(code, off)
            if (getId != null && getId.stringId == backFacingId) {
                require(backFacingIdx < 0) { "Ambiguous backFacing lookup in CameraOverlayZoomButton." }
                backFacingIdx = i
            }
            val cc = HermesHbc96Asm.readCreateClosure(code, off)
            if (cc != null && i >= 2 &&
                ins[i - 2].opcode == HermesHbc96Asm.OP_GET_BY_VAL &&
                (code[ins[i - 2].offset + 2].toInt() and 0xff) == cacheReg
            ) {
                createClosureIdx = i
                closureReg = cc.regDst
                envReg = cc.regEnv
                t1FnId = cc.functionId
            }
        }

        require(cacheInitIdx >= 0 && backFacingIdx >= 0 && createClosureIdx >= 2 && t1FnId >= 0) {
            "Failed to match expected structure in CameraOverlayZoomButton (#${fn.index})."
        }

        val hitGetSlotIdx = createClosureIdx - 3
        val missStoreSlotIdx = findCacheSlotPutPairAfterClosure(code, ins, createClosureIdx, cacheReg, closureReg)

        val hitOff = ins[hitGetSlotIdx].offset
        val hitLen = ins[hitGetSlotIdx].length + ins[hitGetSlotIdx + 1].length
        val missOff = ins[missStoreSlotIdx].offset
        val missLen = ins[missStoreSlotIdx].length + ins[missStoreSlotIdx + 1].length
        val bfInstr = ins[backFacingIdx]
        val bfAccess = HermesHbc96Asm.readGetById(code, bfInstr.offset)!!
        require(bfInstr.length >= 5 && hitLen >= 5 && missLen >= 5) {
            "Unexpected short instruction in CameraOverlayZoomButton (#${fn.index})."
        }

        // Expand React Compiler cache slot array c(12) -> c(13) using slot index 12 for lensSwitch.
        code[ins[cacheInitIdx].offset + 2] = 13

        val postMissOff = ins[missStoreSlotIdx + 2].offset
        val postHitJmpInstr = ins[hitGetSlotIdx + 2]
        val postHitJmpTarget = when (postHitJmpInstr.opcode) {
            HermesHbc96Asm.OP_JMP_LONG ->
                postHitJmpInstr.offset + HermesHbc96.readI32Le(code, postHitJmpInstr.offset + 1)
            HermesHbc96Asm.OP_JMP ->
                postHitJmpInstr.offset + code[postHitJmpInstr.offset + 1].toInt()
            else -> error("Expected Jmp after memo hit in CameraOverlayZoomButton (#${fn.index}).")
        }
        val closureCreateOff = ins[createClosureIdx].offset

        val tails = java.io.ByteArrayOutputStream()
        var cursor = code.size

        // Tail 1: load props.lensSwitch into scratchReg and store in env[newEnvSlot].
        val tail1Off = cursor
        val t1b = HermesHbc96Asm.Builder(tail1Off)
        t1b.raw(code.copyOfRange(bfInstr.offset, bfInstr.offset + bfInstr.length))
        t1b.getById(scratchReg, bfAccess.regObj, newRCache, lensSwitchId)
        t1b.storeToEnvironment(envReg, newEnvSlot, scratchReg)
        t1b.jmpLongToOffset(ins[backFacingIdx + 1].offset)
        val t1Bytes = t1b.build()
        HermesHbc96Asm.overwriteWithJmpLongAndPad(code, bfInstr.offset, bfInstr.length, tail1Off)
        tails.write(t1Bytes)
        cursor += t1Bytes.size

        // Tail 2: verify cached c[12] === lensSwitch (scratchReg) on memo hit path.
        val tail2Off = cursor
        val tmpHitReg = code[ins[hitGetSlotIdx].offset + 1].toInt() and 0xff
        val t2b = HermesHbc96Asm.Builder(tail2Off)
        t2b.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, tmpHitReg, 12)
        t2b.op(HermesHbc96Asm.OP_GET_BY_VAL, tmpHitReg, cacheReg, tmpHitReg)
        t2b.jumpLongToOffset(HermesHbc96Asm.OP_J_STRICT_NOT_EQUAL_LONG, closureCreateOff, tmpHitReg, scratchReg)
        t2b.raw(code.copyOfRange(hitOff, hitOff + hitLen))
        t2b.jmpLongToOffset(postHitJmpTarget)
        val t2Bytes = t2b.build()
        HermesHbc96Asm.overwriteWithJmpLongAndPad(code, hitOff, hitLen, tail2Off)
        tails.write(t2Bytes)
        cursor += t2Bytes.size

        // Tail 3: persist c[12] = lensSwitch (scratchReg) on memo miss path alongside c[3].
        val tail3Off = cursor
        val tmpMissReg = code[missOff + 1].toInt() and 0xff
        val t3b = HermesHbc96Asm.Builder(tail3Off)
        t3b.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, tmpMissReg, 12)
        t3b.op(HermesHbc96Asm.OP_PUT_BY_VAL, cacheReg, tmpMissReg, scratchReg)
        t3b.raw(code.copyOfRange(missOff, missOff + missLen))
        t3b.jmpLongToOffset(postMissOff)
        val t3Bytes = t3b.build()
        HermesHbc96Asm.overwriteWithJmpLongAndPad(code, missOff, missLen, tail3Off)
        tails.write(t3Bytes)

        val combined = code + tails.toByteArray()
        ctx.writeFunctionCode(
            fn = fn,
            newCode = combined,
            newFrameSize = maxOf(fn.frameSize, scratchReg + 1),
            newEnvironmentSize = fn.environmentSize + 1,
            newReadCacheIndex = newRCache,
        )
        return t1FnId to newEnvSlot
    }

    private fun findCacheSlotPutPairAfterClosure(
        code: ByteArray,
        ins: List<HermesHbc96Asm.DecodedInstruction>,
        closureIdx: Int,
        cacheReg: Int,
        closureReg: Int,
    ): Int {
        for (i in (closureIdx + 1) until ins.size - 2) {
            val a = ins[i]
            val b = ins[i + 1]
            if (a.opcode == HermesHbc96Asm.OP_LOAD_CONST_UINT8 &&
                b.opcode == HermesHbc96Asm.OP_PUT_BY_VAL &&
                (code[a.offset + 2].toInt() and 0xff) == 3 &&
                (code[b.offset + 1].toInt() and 0xff) == cacheReg &&
                (code[b.offset + 3].toInt() and 0xff) == closureReg
            ) {
                return i
            }
        }
        error("Could not find cache slot 3 PutByVal in CameraOverlayZoomButton.")
    }

    private fun patchZoomButtonOnPress(
        ctx: HermesHbc96.PatchContext,
        t1Fn: HermesHbc96.FunctionMeta,
        lensSwitchEnvSlot: Int,
    ) {
        val code = ctx.functionCode(t1Fn)
        val ins = HermesHbc96Asm.decodeFunction(code)
        val (maxReg, _) = HermesHbc96Asm.scanMaxRegisterAndReadCache(code, ins)

        require(ins.isNotEmpty() && ins[0].opcode == HermesHbc96Asm.OP_GET_ENVIRONMENT) {
            "Expected GetEnvironment prologue in onPress closure #${t1Fn.index}."
        }
        val envReg = code[ins[0].offset + 1].toInt() and 0xff

        val call4Idx = ins.indexOfFirst { it.opcode == HermesHbc96Asm.OP_CALL4 }
        require(call4Idx > 0 && ins[call4Idx - 1].opcode == HermesHbc96.OP_LOAD_CONST_UNDEFINED) {
            "Expected LoadConstUndefined; Call4 sequence in onPress closure #${t1Fn.index}."
        }
        val undefOff = ins[call4Idx - 1].offset
        val rThis = code[undefOff + 1].toInt() and 0xff
        val callOff = ins[call4Idx].offset
        val rDst = code[callOff + 1].toInt() and 0xff
        val rFn = code[callOff + 2].toInt() and 0xff
        val rNeutral = code[callOff + 4].toInt() and 0xff
        val rCurr = code[callOff + 5].toInt() and 0xff
        val rMin = code[callOff + 6].toInt() and 0xff
        val returnOff = ins[call4Idx + 1].offset

        // Hermes Call pushes arguments from (frameSize - 7) downward: ThisArg, arg1..arg4.
        val newFrameSize = maxOf(t1Fn.frameSize, maxReg + 1 + 11)
        require(newFrameSize < 128) { "Required frameSize $newFrameSize exceeds SmallFuncHeader limit." }
        val slotThis = newFrameSize - 7
        val slotArg1 = newFrameSize - 8
        val slotArg2 = newFrameSize - 9
        val slotArg3 = newFrameSize - 10
        val slotArg4 = newFrameSize - 11

        val tailOff = code.size
        val b = HermesHbc96Asm.Builder(tailOff)
        b.loadFromEnvironment(slotArg4, envReg, lensSwitchEnvSlot)
        b.op(HermesHbc96.OP_LOAD_CONST_UNDEFINED, rThis)
        b.op(HermesHbc96.OP_LOAD_CONST_UNDEFINED, slotThis)
        b.op(HermesHbc96Asm.OP_MOV, slotArg1, rNeutral)
        b.op(HermesHbc96Asm.OP_MOV, slotArg2, rCurr)
        b.op(HermesHbc96Asm.OP_MOV, slotArg3, rMin)
        b.op(HermesHbc96Asm.OP_CALL, rDst, rFn, 5)
        b.jmpLongToOffset(returnOff)
        val tailBytes = b.build()

        HermesHbc96Asm.overwriteWithJmpLongAndPad(
            code = code,
            patchOffset = undefOff,
            replacedLength = returnOff - undefOff,
            targetOffset = tailOff,
        )

        ctx.writeFunctionCode(
            fn = t1Fn,
            newCode = code + tailBytes,
            newFrameSize = newFrameSize,
        )
    }

    private fun rewriteGetNextZoomValue(
        ctx: HermesHbc96.PatchContext,
        fn: HermesHbc96.FunctionMeta,
        zoomThreshold: Double,
        zoomTolerance: Double,
    ) {
        val thresholdInt = zoomThreshold.toInt()
        val isWholeByte = thresholdInt.toDouble() == zoomThreshold && thresholdInt in 0..255

        val b = HermesHbc96Asm.Builder(0)
        b.op(HermesHbc96Asm.OP_LOAD_PARAM, 0, 1) // neutralZoom (1x)
        b.op(HermesHbc96Asm.OP_LOAD_PARAM, 1, 2) // currentZoom
        b.op(HermesHbc96Asm.OP_LOAD_PARAM, 2, 3) // minZoom (0.5x)
        b.op(HermesHbc96Asm.OP_LOAD_PARAM, 3, 4) // telephotoEnabled
        b.jumpLong(HermesHbc96Asm.OP_JMP_FALSE_LONG, "no_tele", 3)

        b.loadConstDouble(4, zoomTolerance)
        if (isWholeByte) {
            b.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, 5, thresholdInt)
        } else {
            b.loadConstDouble(5, zoomThreshold)
        }
        b.op(HermesHbc96Asm.OP_SUB, 6, 5, 4) // 3 - 0.05 = 2.95
        b.jumpLong(HermesHbc96Asm.OP_J_NOT_LESS_LONG, "no_ultrawide", 2, 0)

        // Device supports 0.5x + 1x + 3x: cycle 0.5 -> 1 -> 3 -> 0.5.
        b.op(HermesHbc96Asm.OP_SUB, 7, 0, 4) // neutralZoom - 0.05
        b.jumpLong(HermesHbc96Asm.OP_J_NOT_LESS_LONG, "check_3x", 1, 7)
        b.op(HermesHbc96.OP_RET, 0)
        b.label("check_3x")
        b.jumpLong(HermesHbc96Asm.OP_J_NOT_LESS_LONG, "ret_min", 1, 6)
        b.op(HermesHbc96.OP_RET, 5)
        b.label("ret_min")
        b.op(HermesHbc96.OP_RET, 2)

        // Device supports 1x + 3x only: toggle 1 <-> 3.
        b.label("no_ultrawide")
        b.jumpLong(HermesHbc96Asm.OP_J_NOT_LESS_LONG, "ret_neutral", 1, 6)
        b.op(HermesHbc96.OP_RET, 5)
        b.label("ret_neutral")
        b.op(HermesHbc96.OP_RET, 0)

        // Non-telephoto / front camera: original 0.5x <-> 1x behavior.
        b.label("no_tele")
        b.jumpLong(HermesHbc96Asm.OP_J_LESS_LONG, "orig_neutral", 0, 1)
        b.jumpLong(HermesHbc96Asm.OP_J_NOT_LESS_LONG, "orig_neutral", 2, 1)
        b.jumpLong(HermesHbc96Asm.OP_J_LESS_EQUAL_LONG, "orig_min", 1, 0)
        b.op(HermesHbc96.OP_RET, 0)
        b.label("orig_min")
        b.op(HermesHbc96.OP_RET, 2)
        b.label("orig_neutral")
        b.op(HermesHbc96.OP_RET, 0)

        ctx.writeFunctionCode(
            fn = fn,
            newCode = b.build(),
            newParamCount = 5,
            newFrameSize = 8,
            newEnvironmentSize = 0,
            newReadCacheIndex = 0,
            newWriteCacheIndex = 0,
        )
    }

    private fun patchHomeCameraZoomDetection(
        ctx: HermesHbc96.PatchContext,
        homeFn: HermesHbc96.FunctionMeta,
        zoomThreshold: Double,
    ): Int {
        val idDevice = ctx.stringIds.getValue("device")
        val idZoomProps = ctx.stringIds.getValue("zoomProps")
        val idMinZoom = ctx.stringIds.getValue("minZoom")
        val idNeutralZoom = ctx.stringIds.getValue("neutralZoom")
        val idZoom = ctx.stringIds.getValue("zoom")
        val idBack = ctx.stringIds.getValue("back")
        val idBackFacing = ctx.stringIds.getValue("backFacing")
        val idCameraTheme = ctx.stringIds.getValue("camera_theme")
        val idLensSwitch = ctx.stringIds.getValue("lensSwitch")
        val idMaxZoom = ctx.stringIds.getValue("maxZoom")
        val idTelephone = ctx.stringIds.getValue("telephone")
        val idSlice = ctx.stringIds.getValue("slice")
        val idPhoto = ctx.stringIds.getValue("photo")
        val idType = ctx.stringIds.getValue("type")
        val idPhysicalDevices = ctx.stringIds.getValue("physicalDevices")
        val idArray = ctx.stringIds.getValue("Array")
        val idIsArray = ctx.stringIds.getValue("isArray")
        val idLength = ctx.stringIds.getValue("length")

        val code = ctx.functionCode(homeFn)
        val ins = HermesHbc96Asm.decodeFunction(code)
        val (maxReg, maxRCache) = HermesHbc96Asm.scanMaxRegisterAndReadCache(code, ins)

        var rDevice = -1
        var rZoomProps = -1
        var overlaySiteIdx = -1
        var rOverlayProps = -1
        var rMin = -1
        var rNeutral = -1
        var rCamPos = -1

        for (i in ins.indices) {
            val put = HermesHbc96Asm.readPutNewOwnById(code, ins[i].offset) ?: continue
            when (put.stringId) {
                idDevice -> rDevice = put.regVal
                idZoomProps -> rZoomProps = put.regVal
                idBackFacing -> {
                    if (i >= 5) {
                        val p0 = HermesHbc96Asm.readPutNewOwnById(code, ins[i - 5].offset)
                        val p1 = HermesHbc96Asm.readPutNewOwnById(code, ins[i - 4].offset)
                        val p2 = HermesHbc96Asm.readPutNewOwnById(code, ins[i - 3].offset)
                        val strBack = HermesHbc96Asm.readLoadConstString(code, ins[i - 2].offset)
                        if (p0?.stringId == idMinZoom &&
                            p1?.stringId == idNeutralZoom &&
                            p2?.stringId == idZoom &&
                            strBack?.second == idBack &&
                            ins[i - 1].opcode == HermesHbc96Asm.OP_STRICT_EQ
                        ) {
                            val strictEqOff = ins[i - 1].offset
                            require((code[strictEqOff + 1].toInt() and 0xff) == put.regVal) {
                                "Unexpected register flow at backFacing property in Home (#${homeFn.index})."
                            }
                            require(overlaySiteIdx < 0) {
                                "Ambiguous overlayZoomButtonProps sequence in Home (#${homeFn.index})."
                            }
                            overlaySiteIdx = i
                            rOverlayProps = put.regObj
                            rMin = p0.regVal
                            rNeutral = p1.regVal
                            val opA = code[strictEqOff + 2].toInt() and 0xff
                            val opB = code[strictEqOff + 3].toInt() and 0xff
                            rCamPos = if (opA == strBack.first) opB else opA
                        }
                    }
                }
            }
        }

        require(rDevice >= 0 && rZoomProps >= 0 && overlaySiteIdx >= 0 && rMin >= 0 && rNeutral >= 0 && rCamPos >= 0) {
            "Failed to match Home overlayZoomButtonProps sequence (#${homeFn.index})."
        }

        var showZoomIdx = -1
        for (i in 0 until overlaySiteIdx - 1) {
            val cur = ins[i]
            val next = ins[i + 1]
            if (cur.opcode == HermesHbc96Asm.OP_LESS &&
                (code[cur.offset + 2].toInt() and 0xff) == rMin &&
                (code[cur.offset + 3].toInt() and 0xff) == rNeutral
            ) {
                val strNext = HermesHbc96Asm.readLoadConstString(code, next.offset)
                if (strNext != null && strNext.second == idCameraTheme) {
                    showZoomIdx = i
                    break
                }
            }
        }
        require(showZoomIdx >= 0) { "Failed to match Home zoom-visibility gate before camera_theme." }

        val rShowZoom = code[ins[showZoomIdx].offset + 1].toInt() and 0xff
        val site1Off = ins[showZoomIdx].offset
        val site1Len = ins[showZoomIdx].length + ins[showZoomIdx + 1].length
        val site1ResumeOff = ins[showZoomIdx + 2].offset
        val origPostLessBytes = code.copyOfRange(ins[showZoomIdx + 1].offset, site1ResumeOff)

        val site2Off = ins[overlaySiteIdx].offset
        val site2Len = ins[overlaySiteIdx].length
        val site2ResumeOff = ins[overlaySiteIdx + 1].offset
        val origPutBackFacingBytes = code.copyOfRange(site2Off, site2ResumeOff)

        val rTele = maxReg + 1
        val s0 = maxReg + 2
        val s1 = maxReg + 3
        val s2 = maxReg + 4
        val s3 = maxReg + 5
        val s4 = maxReg + 6
        val s5 = maxReg + 7
        val rcBase = maxRCache
        require(s5 < 128 && rcBase + 7 <= 0xff) {
            "Home register/cache budget exhausted (maxReg=$maxReg, maxRCache=$maxRCache)."
        }

        // Tail A: compute telephoto availability for back camera and widen ZoomOverlay visibility.
        val tailAOff = code.size
        val a = HermesHbc96Asm.Builder(tailAOff)
        a.op(HermesHbc96Asm.OP_LESS, rShowZoom, rMin, rNeutral)
        a.op(HermesHbc96.OP_LOAD_CONST_FALSE, rTele)
        a.loadConstString(s0, idBack)
        a.jumpLong(HermesHbc96Asm.OP_J_STRICT_NOT_EQUAL_LONG, "done", rCamPos, s0)
        a.jumpLong(HermesHbc96Asm.OP_JMP_FALSE_LONG, "done", rDevice)
        a.getById(s0, rZoomProps, rcBase + 1, idMaxZoom)
        val thresholdByte = zoomThreshold.toInt()
        if (thresholdByte.toDouble() == zoomThreshold && thresholdByte in 0..255) {
            a.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, s1, thresholdByte)
        } else {
            a.loadConstDouble(s1, zoomThreshold)
        }
        a.jumpLong(HermesHbc96Asm.OP_J_LESS_LONG, "done", s0, s1)

        // Build exact VisionCamera DeviceType string "telephoto" from bundle strings.
        a.loadConstString(s0, idTelephone)
        a.getById(s1, s0, rcBase + 2, idSlice)
        a.op(HermesHbc96.OP_LOAD_CONST_ZERO, s2)
        a.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, s3, 4)
        a.op(HermesHbc96Asm.OP_CALL3, s0, s1, s0, s2, s3)
        a.loadConstString(s1, idPhoto)
        a.op(HermesHbc96Asm.OP_ADD, s0, s0, s1) // s0 = "telephoto"

        a.getById(s1, rDevice, rcBase + 3, idType)
        a.jumpLong(HermesHbc96Asm.OP_J_STRICT_EQUAL_LONG, "found", s1, s0)
        a.getById(s1, rDevice, rcBase + 4, idPhysicalDevices)
        a.jumpLong(HermesHbc96Asm.OP_JMP_FALSE_LONG, "done", s1)
        a.op(HermesHbc96Asm.OP_GET_GLOBAL_OBJECT, s2)
        a.tryGetById(s3, s2, rcBase + 5, idArray)
        a.getById(s4, s3, rcBase + 6, idIsArray)
        a.op(HermesHbc96Asm.OP_CALL2, s2, s4, s3, s1)
        a.jumpLong(HermesHbc96Asm.OP_JMP_FALSE_LONG, "done", s2)
        a.getById(s2, s1, rcBase + 7, idLength)
        a.op(HermesHbc96.OP_LOAD_CONST_ZERO, s3) // index
        a.op(HermesHbc96Asm.OP_LOAD_CONST_UINT8, s4, 1) // step

        a.label("loop")
        a.jumpLong(HermesHbc96Asm.OP_J_NOT_LESS_LONG, "done", s3, s2)
        a.op(HermesHbc96Asm.OP_GET_BY_VAL, s5, s1, s3)
        a.jumpLong(HermesHbc96Asm.OP_JMP_FALSE_LONG, "next", s5)
        a.getById(s5, s5, rcBase + 3, idType)
        a.jumpLong(HermesHbc96Asm.OP_J_STRICT_EQUAL_LONG, "found", s5, s0)
        a.label("next")
        a.op(HermesHbc96Asm.OP_ADD, s3, s3, s4)
        a.jumpLong(HermesHbc96Asm.OP_JMP_LONG, "loop")

        a.label("found")
        a.op(HermesHbc96.OP_LOAD_CONST_TRUE, rTele)
        a.op(HermesHbc96.OP_LOAD_CONST_TRUE, rShowZoom)

        a.label("done")
        a.raw(origPostLessBytes)
        a.jmpLongToOffset(site1ResumeOff)
        val tailABytes = a.build()
        HermesHbc96Asm.overwriteWithJmpLongAndPad(code, site1Off, site1Len, tailAOff)

        // Tail B: attach lensSwitch flag to overlayZoomButtonProps before CameraZoomOverlay jsx().
        val tailBOff = code.size + tailABytes.size
        val b = HermesHbc96Asm.Builder(tailBOff)
        b.raw(origPutBackFacingBytes)
        b.putNewOwnById(rOverlayProps, rTele, idLensSwitch)
        b.jmpLongToOffset(site2ResumeOff)
        val tailBBytes = b.build()
        HermesHbc96Asm.overwriteWithJmpLongAndPad(code, site2Off, site2Len, tailBOff)

        return ctx.writeFunctionCode(
            fn = homeFn,
            newCode = code + tailABytes + tailBBytes,
            newFrameSize = maxOf(homeFn.frameSize, s5 + 1),
            newReadCacheIndex = rcBase + 7,
        )
    }

    private fun resolveUniqueFunction(
        ctx: HermesHbc96.PatchContext,
        name: String,
        predicate: (HermesHbc96.FunctionMeta) -> Boolean,
    ): HermesHbc96.FunctionMeta {
        val nameId = ctx.stringIds.getValue(name)
        val matches = ctx.functionsByNameId.getValue(nameId).filter(predicate)
        require(matches.size == 1) {
            "Expected 1 function matching '$name', found ${matches.size}."
        }
        return matches[0]
    }
}
