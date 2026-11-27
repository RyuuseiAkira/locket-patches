// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/camera/EnableTelephotoZoomTogglePatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Enable telephoto 3x zoom toggle patch

package io.github.ryuuseiakira.locket.patches.locket.camera

import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Extends Locket's viewfinder zoom preset pill from `0.5x <-> 1x` to cycle `0.5x -> 1x -> 3x` (or
 * `1x <-> 3x` on phones without an ultra-wide sensor) when a telephoto camera is available on the
 * back camera.
 *
 * Attachment: `assets/index.android.bundle` (`Home`, `CameraOverlayZoomButton`, its `onPress`
 * closure, and `getNextZoomValue`).
 * Mechanism: Inspects VisionCamera's back `device.type` and `device.physicalDevices` for
 * `"telephoto"` alongside `zoomProps.maxZoom >= 3`, surfaces the flag on `overlayZoomButtonProps`
 * (`lensSwitch`), tracks it in React Compiler's memo cache, and relocates the expanded functions
 * cleanly before `debugInfoOffset` with updated HBC headers and SHA-1 footer.
 * Constraint: Android's VisionCamera `zoomLensSwitchFactors` returns an empty array, so telephoto
 * availability is determined from `device.type` / `device.physicalDevices[].type`.
 */
@Suppress("unused")
val enableTelephotoZoomTogglePatch = patch(
    name = "Enable telephoto zoom toggle",
    description = "Adds a 3x telephoto preset to the camera zoom toggle button when a telephoto camera is available.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.EnableTelephotoZoomToggle(
                zoomThreshold = 3.0,
                zoomTolerance = 0.05,
            ),
        )
    }
}
