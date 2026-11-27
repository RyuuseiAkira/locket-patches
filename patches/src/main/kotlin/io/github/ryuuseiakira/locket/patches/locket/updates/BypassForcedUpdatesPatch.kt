// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/updates/BypassForcedUpdatesPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Bypass forced updates patch

package io.github.ryuuseiakira.locket.patches.locket.updates

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

private val appUpdateStartUpdateFingerprint = Fingerprint(
    definingClass = "Lcom/locket/Locket/AppUpdateModule;",
    name = "startUpdate",
    parameters = listOf("I"),
    returnType = "V",
)

/**
 * Bypasses remote-config forced/recommended update checks, Google Play in-app update flows, and
 * automatic Play Store review prompts.
 *
 * Attachment: `assets/index.android.bundle` async generator coroutines (`checkForUpdates`,
 * `_shouldPromptForReview`, auto review prompt) and `AppUpdateModule.startUpdate(I)V` in DEX.
 * Mechanism: Neuters matched async generator bodies right after `ResumeGenerator` + `JmpTrue[Long]`
 * (preserving async Promise completion and avoiding `new RegExp("")` matching every version), and
 * returns early from `AppUpdateModule.startUpdate`.
 * Constraint: Generator rewrite assumes standard `StartGenerator; ResumeGenerator; JmpTrue[Long]`
 * prologue and leaves explicit Settings review buttons untouched.
 */
@Suppress("unused")
val bypassForcedUpdatesPatch = patch(
    name = "Bypass forced updates",
    description = "Prevents forced update dialogs, Google Play in-app update flows, and automatic review prompts.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.GeneratorEarlyReturn(
                functionName = "?anon_0_",
                requiredStrings = listOf(
                    "forceUpgradeVersionPattern",
                    "recommendUpgradeVersionPattern",
                ),
                returnOpcode = HermesHbc96.OP_LOAD_CONST_UNDEFINED,
            ),
            HermesHbc96.Mutation.GeneratorEarlyReturn(
                functionName = "?anon_0_",
                requiredStrings = listOf(
                    "currentUser",
                    "getNumSentLockets",
                ),
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.GeneratorEarlyReturn(
                functionName = "?anon_0_",
                requiredStrings = listOf(
                    "logPromptedForStoreReview",
                    "requestReview",
                ),
                returnOpcode = HermesHbc96.OP_LOAD_CONST_UNDEFINED,
            ),
        )

        appUpdateStartUpdateFingerprint.method.returnEarly()
    }
}
