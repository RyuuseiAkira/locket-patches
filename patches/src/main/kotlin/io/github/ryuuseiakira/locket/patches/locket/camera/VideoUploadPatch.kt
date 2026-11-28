// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/camera/VideoUploadPatch.kt
// Kotlin / Morphe Patcher 2.6.0 (JVM 11, Android API 26) / Locket Widget gallery video upload patch

package io.github.ryuuseiakira.locket.patches.locket.camera

import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.locket.gold.unlockGoldPatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Enables picking videos from Android's gallery/photo picker and routing them into Locket's
 * Media3 `VideoTransformer` square-crop, preview, thumbnail, and upload pipeline.
 *
 * Attachment: `assets/index.android.bundle` (`useCameraRoll` module initializer, `openCameraRoll`
 * generator, and `Home`'s `useCameraRoll` `onSuccess` closure).
 * Mechanism: Expands picker `MediaTypeOptions.Images` to `MediaTypeOptions.All`, raises the
 * pre-transcode file size ceiling to 512 MiB, attaches `fileType: asset.type` in-place onto the
 * callback payload, and relocates `Home`'s `onSuccess` closure before the SHA-1 footer so picked
 * videos enter `onRecordingFinished` while picked images keep `HomeImageCrop` unchanged.
 * Constraint: Depends on `unlockGoldPatch` and `spoofSignaturePatch` so the `'camera_roll'`
 * subscriber gate is enabled on the Home screen.
 */
@Suppress("unused")
val videoUploadPatch = patch(
    name = "Upload videos from camera roll",
    description = "Allows selecting and uploading videos from the device gallery alongside photos.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(
        spoofSignaturePatch,
        unlockGoldPatch,
    )

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.EnableCameraRollVideoUpload(),
        )
    }
}
