// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/camera/ImproveZoomGesturePatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Improve camera zoom gesture patch

package io.github.ryuuseiakira.locket.patches.locket.camera

import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Replaces Locket's linear clamped pinch-to-zoom interpolation with smooth multiplicative
 * exponential scaling clamped to `[minZoom, maxZoom]` across both the Reanimated UI worklet's
 * `__initData.code` and its fallback Hermes bytecode.
 *
 * Attachment: `assets/index.android.bundle` (`HomeCameraTsx3Factory` and `HomeCameraTsx3`).
 * Mechanism: Updates `HomeCameraTsx3Factory` to synthesize a fresh `__initData` `{ code }` object
 * from existing bundle tokens using `pinchStartZoom.value * Math.pow(Math.max(0.01, event.scale),
 * 1.8)` clamped to `[minZoom, maxZoom]` (without touching shared string storage bytes), and patches
 * `HomeCameraTsx3` bytecode to match.
 * Constraint: Preserves string storage immutability because Hermes deduplicates identifier substrings
 * (`maxZoom`, `minZoom`, `pinchStartZoom`, `SCALE_FULL_ZOOM`) inside the original worklet string.
 */
@Suppress("unused")
val improveZoomGesturePatch = patch(
    name = "Improve zoom gesture",
    description = "Makes camera pinch-to-zoom smooth and natural instead of jumping abruptly across hardware zoom bounds.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.ImprovePinchZoomWorklet(
                factoryFunctionName = "HomeCameraTsx3Factory",
                workletFunctionName = "HomeCameraTsx3",
                exponent = 1.8,
                minScaleClamp = 0.01,
            ),
        )
    }
}
