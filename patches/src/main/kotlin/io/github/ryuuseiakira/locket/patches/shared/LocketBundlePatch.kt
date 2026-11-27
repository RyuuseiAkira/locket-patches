// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/LocketBundlePatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Shared APK Hermes resource patch helper

package io.github.ryuuseiakira.locket.patches.shared

import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.resourceFile

/**
 * Loads `assets/index.android.bundle` from the target APK/APKM resource workspace, applies
 * [mutations] via [HermesHbc96], and writes the modified bundle back in place.
 */
internal fun patchLocketBundle(vararg mutations: HermesHbc96.Mutation): HermesHbc96.BatchPatchResult {
    val bundleFile = resourceFile(HermesHbc96.BUNDLE_PATH, copy = true)
    if (!bundleFile.isFile) {
        throw PatchException("Target APK does not contain ${HermesHbc96.BUNDLE_PATH}.")
    }

    val result = try {
        HermesHbc96.patch(bundleFile.readBytes(), mutations.toList())
    } catch (ex: IllegalArgumentException) {
        throw PatchException(ex.message ?: "Failed to patch ${HermesHbc96.BUNDLE_PATH}.", ex)
    }

    bundleFile.writeBytes(result.bytes)
    return result
}
