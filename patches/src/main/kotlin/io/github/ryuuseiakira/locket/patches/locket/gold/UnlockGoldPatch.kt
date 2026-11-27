// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/gold/UnlockGoldPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Unlock Gold patch

package io.github.ryuuseiakira.locket.patches.locket.gold

import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.patch
import app.morphe.patcher.patch.resourceFile
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET

private const val BUNDLE_PATH = "assets/index.android.bundle"

@Suppress("unused")
val unlockGoldPatch = patch(
    name = "Unlock Gold",
    description = "Unlocks client-side Locket Gold features by overriding the remote config subscription check.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        val bundleFile = resourceFile(BUNDLE_PATH, copy = true)
        if (!bundleFile.isFile) {
            throw PatchException("Target APK does not contain $BUNDLE_PATH.")
        }

        val patched = try {
            HermesBundlePatcher.patch(bundleFile.readBytes())
        } catch (ex: IllegalArgumentException) {
            throw PatchException(ex.message ?: "Failed to patch $BUNDLE_PATH.", ex)
        }

        bundleFile.writeBytes(patched.bytes)
    }
}
