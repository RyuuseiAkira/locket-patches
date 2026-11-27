// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/ui/HideUpgradePromptsPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Hide upgrade and invite prompts patch

package io.github.ryuuseiakira.locket.patches.locket.ui

import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Hides client-side subscription upsell buttons, feature discovery popups, settings upsells, and
 * rewarded referral banners/popups.
 *
 * Attachment: `assets/index.android.bundle` (`androidSubscribeGoldButtonEnabled`,
 * `getFeatureDiscoveryPopupConfig`, `settingsUpsellFeatures`, `rewardedReferralsConfig`,
 * `linkReferralsEnabled`, and `isEligibleForRewardedReferralsPopup`).
 * Mechanism: Sets prompt/gate flags to `false` or `null` and `settingsUpsellFeatures` to `{}` so
 * callers take their built-in empty/disabled branches without null-dereference errors.
 * Constraint: Opt-in (`default = false`) to preserve Settings Gold management and referral UI for
 * users who want them.
 */
@Suppress("unused")
val hideUpgradePromptsPatch = patch(
    name = "Hide upgrade and invite prompts",
    description = "Hides Gold subscription banners, feature discovery popups, settings upsells, and rewarded referral prompts.",
    default = false,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "androidSubscribeGoldButtonEnabled",
                getterMethodName = "getBoolean",
                configKey = "android_subscribe_gold_button_enabled",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "getFeatureDiscoveryPopupConfig",
                replacement = byteArrayOf(
                    HermesHbc96.OP_LOAD_CONST_NULL,
                    0x00,
                    HermesHbc96.OP_RET,
                    0x00,
                ),
                requiredStrings = listOf("feature_discovery_popup_config"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "settingsUpsellFeatures",
                replacement = byteArrayOf(
                    HermesHbc96.OP_NEW_OBJECT,
                    0x00,
                    HermesHbc96.OP_RET,
                    0x00,
                ),
                requiredStrings = listOf("android_upsell_features"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "rewardedReferralsConfig",
                replacement = byteArrayOf(
                    HermesHbc96.OP_LOAD_CONST_NULL,
                    0x00,
                    HermesHbc96.OP_RET,
                    0x00,
                ),
                requiredStrings = listOf("rewarded_referrals_popup_config"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "linkReferralsEnabled",
                replacement = byteArrayOf(
                    HermesHbc96.OP_LOAD_CONST_FALSE,
                    0x00,
                    HermesHbc96.OP_RET,
                    0x00,
                ),
                requiredStrings = listOf("rewardedReferralsConfig", "gold"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "isEligibleForRewardedReferralsPopup",
                replacement = byteArrayOf(
                    HermesHbc96.OP_LOAD_CONST_FALSE,
                    0x00,
                    HermesHbc96.OP_RET,
                    0x00,
                ),
                requiredStrings = listOf("linkReferralsEnabled", "isPaidGoldSubscriber"),
            ),
        )
    }
}
