// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/ads/RemoveAdsPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Remove ads patch

package io.github.ryuuseiakira.locket.patches.locket.ads

import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Disables History feed ads, ad impression/reporting flags, and client-side ad eligibility.
 *
 * Attachment: `assets/index.android.bundle` (`androidHistoryAdsEnabled`,
 * `androidHistoryAdsReportingEnabled`, and `isUserEligibleForAds`).
 * Mechanism: Overrides Remote Config `Call2` getters to `false` and short-circuits
 * `isUserEligibleForAds` to `LoadConstFalse r0; Ret r0`.
 * Constraint: Fixed-length HBC v96 rewrites depend on unique named helper functions.
 */
@Suppress("unused")
val removeAdsPatch = patch(
    name = "Remove ads",
    description = "Disables history feed ads, ad reporting, and client-side ad eligibility gates.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "androidHistoryAdsEnabled",
                getterMethodName = "getBoolean",
                configKey = "android_history_ads_enabled",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "androidHistoryAdsReportingEnabled",
                getterMethodName = "getBoolean",
                configKey = "android_history_ads_reporting_enabled",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "isUserEligibleForAds",
                replacement = byteArrayOf(
                    HermesHbc96.OP_LOAD_CONST_FALSE,
                    0x00,
                    HermesHbc96.OP_RET,
                    0x00,
                ),
                requiredStrings = listOf("historyAdsEarliestLegalNoticeDate"),
            ),
        )
    }
}
