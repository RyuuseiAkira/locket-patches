// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/camera/DefaultBackCameraPatch.kt
// kotlin / DefaultBackCameraPatch / morphe-patcher 2.6.0 / com.locket.Locket (API 26)

package io.github.ryuuseiakira.locket.patches.locket.camera

import app.morphe.patcher.patch.patch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Switches Locket's initial `Home` camera `useState('front')` state to `'back'` while preserving
 * the camera flip toggle, Dual Camera mode, and QR scanner.
 */
@Suppress("unused")
val defaultBackCameraPatch = patch(
    name = "Default back camera",
    description = "Starts the main camera on the back lens instead of the front selfie camera.",
    default = false,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.ReplaceCallStringConst(
                functionName = "Home",
                calleeName = "useState",
                fromValue = "front",
                toValue = "back",
                requiredStrings = listOf(
                    "useCameraDevice",
                    "cameraPosition",
                    "front",
                    "back",
                ),
            ),
        )
    }
}
