// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/gold/UnlockGoldPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Unlock Gold patch

package io.github.ryuuseiakira.locket.patches.locket.gold

import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

/**
 * Enables client-side Locket Gold gates by rewriting `androidGoldSubscriptionOverride` to return
 * `true` without querying Firebase Remote Config.
 *
 * Attachment: `assets/index.android.bundle` (`androidGoldSubscriptionOverride` helper).
 * Mechanism: In-place 5-byte HBC v96 `Call2 -> LoadConstTrue; Ret; Unreachable` rewrite plus
 * `spoofSignaturePatch` so Firebase Auth, Remote Config, and App Check accept re-signed APKs.
 * Constraint: Server-side entitlement validation and Play billing receipts remain server-enforced.
 */
@Suppress("unused")
val unlockGoldPatch = patch(
    name = "Unlock Gold",
    description = "Unlocks client-side Locket Gold features by overriding the remote config subscription check.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        patchLocketBundle(
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "androidGoldSubscriptionOverride",
                getterMethodName = "getBoolean",
                configKey = "android_gold_subscription_override",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_TRUE,
            ),
        )
    }
}
