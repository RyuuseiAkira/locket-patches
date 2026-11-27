// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/privacy/DisableTrackingPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Disable tracking and analytics patch

package io.github.ryuuseiakira.locket.patches.locket.privacy

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import io.github.ryuuseiakira.locket.patches.shared.HermesHbc96
import io.github.ryuuseiakira.locket.patches.shared.patchLocketBundle

private const val FIREBASE_ANALYTICS_CLASS = "Lcom/google/firebase/analytics/FirebaseAnalytics;"
private const val RN_APPSFLYER_MODULE_CLASS = "Lcom/appsflyer/reactnative/RNAppsFlyerModule;"

private val cameraDebugSetTelemetryFingerprint = Fingerprint(
    definingClass = "Lcom/locket/Locket/CameraDebug/CameraDebugModule;",
    name = "setTelemetryEnabled",
    parameters = listOf("Z"),
    returnType = "Z",
)

private val firebaseSetAnalyticsCollectionEnabledFingerprint = Fingerprint(
    definingClass = FIREBASE_ANALYTICS_CLASS,
    isStatic = false,
    parameters = listOf("Z"),
    returnType = "V",
)

private val firebaseVoidHookParamLists = listOf(
    listOf("Ljava/lang/String;", "Landroid/os/Bundle;"),
    emptyList(),
    listOf("Landroid/os/Bundle;"),
    listOf("J"),
    listOf("Ljava/lang/String;"),
    listOf("Ljava/lang/String;", "Ljava/lang/String;"),
    listOf("Landroid/app/Activity;", "Ljava/lang/String;", "Ljava/lang/String;"),
)

private val appsFlyerVoidHooks: List<Pair<String, List<String>>> = listOf(
    "startSdk" to emptyList(),
    "performOnDeepLinking" to emptyList(),
    "logAdRevenue" to listOf("Lcom/facebook/react/bridge/ReadableMap;"),
    "logCrossPromotionImpression" to listOf(
        "Ljava/lang/String;",
        "Ljava/lang/String;",
        "Lcom/facebook/react/bridge/ReadableMap;",
    ),
    "setConsentData" to listOf("Lcom/facebook/react/bridge/ReadableMap;"),
    "initSdkWithCallBack" to listOf(
        "Lcom/facebook/react/bridge/ReadableMap;",
        "Lcom/facebook/react/bridge/Callback;",
        "Lcom/facebook/react/bridge/Callback;",
    ),
    "logEvent" to listOf(
        "Ljava/lang/String;",
        "Lcom/facebook/react/bridge/ReadableMap;",
        "Lcom/facebook/react/bridge/Callback;",
        "Lcom/facebook/react/bridge/Callback;",
    ),
)

/**
 * Disables client-side attribution, telemetry, Sentry performance/session capture, Amplitude event
 * logging, AppsFlyer reporting, native camera debug telemetry, and Firebase Analytics logging.
 *
 * Attachment: `assets/index.android.bundle` Remote Config getters and telemetry helpers plus
 * `CameraDebugModule`, `FirebaseAnalytics`, and `RNAppsFlyerModule` in DEX.
 * Mechanism: Sets Sentry sample rates to `0` and tracking/debug flags to `false`, neuters JS
 * telemetry dispatchers, forces `FirebaseAnalytics` collection enabled argument to `false` while
 * returning early from analytics logging/property setters, and disables native `CameraDebug` and
 * `RNAppsFlyerModule` entry points.
 * Constraint: Preserves `FirebaseAnalytics` ID/consent task stubs, Crashlytics JS boundaries, and
 * core Firebase Auth/Messaging/App Check transport.
 */
@Suppress("unused")
val disableTrackingPatch = patch(
    name = "Disable tracking and analytics",
    description = "Disables AppsFlyer, Amplitude, Sentry tracing, Firebase Analytics logging, and native camera debug telemetry.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        val earlyReturnUndefined = byteArrayOf(
            HermesHbc96.OP_LOAD_CONST_UNDEFINED,
            0x00,
            HermesHbc96.OP_RET,
            0x00,
        )

        patchLocketBundle(
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "androidReadopsAmplitudeLogging",
                getterMethodName = "getBoolean",
                configKey = "android_readops_amplitude_logging",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "androidSendDebugInfo",
                getterMethodName = "getBoolean",
                configKey = "android_send_debug_info",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "sentryPerformanceTracking",
                getterMethodName = "getBoolean",
                configKey = "sentry_performance_tracking",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "sentrySessionTracking",
                getterMethodName = "getBoolean",
                configKey = "sentry_session_tracking",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "sentryTombstone",
                getterMethodName = "getBoolean",
                configKey = "sentry_tombstone",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_FALSE,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "sentrySampleRate",
                getterMethodName = "getNumber",
                configKey = "sentry_sample_rate",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_ZERO,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "sentryTracesSampleRate",
                getterMethodName = "getNumber",
                configKey = "sentry_trace_sample_rate",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_ZERO,
            ),
            HermesHbc96.Mutation.RemoteConfigReturnConst(
                functionName = "sentryProfilesSampleRate",
                getterMethodName = "getNumber",
                configKey = "sentry_profiles_sample_rate",
                returnOpcode = HermesHbc96.OP_LOAD_CONST_ZERO,
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "initAppsFlyer",
                replacement = earlyReturnUndefined,
                requiredStrings = listOf("appsFlyer", "initSdk"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "logAppsFlyerEvent",
                replacement = earlyReturnUndefined,
                requiredStrings = listOf("logEvent"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "logEventToAppsFlyer",
                replacement = earlyReturnUndefined,
                requiredStrings = listOf("logAppsFlyerEvent"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "enableAdServicesAttributionTokenCollection",
                replacement = earlyReturnUndefined,
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "initAmplitudeFlags",
                replacement = earlyReturnUndefined,
                requiredStrings = listOf("Identify", "identify"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "logEventToAmplitudeIfEnabled",
                replacement = earlyReturnUndefined,
                requiredStrings = listOf("isAmplitudeEventRemotelyEnabled", "logEvent"),
            ),
            HermesHbc96.Mutation.FunctionEarlyReturn(
                functionName = "setNativeTelemetryEnabled",
                replacement = earlyReturnUndefined,
                requiredStrings = listOf("CameraDebug", "setTelemetryEnabled"),
            ),
        )

        cameraDebugSetTelemetryFingerprint.method.returnEarly(false)

        // Parameter p1 register is (registerCount - 1) for non-static (Z)V.
        val analyticsEnableMethod = firebaseSetAnalyticsCollectionEnabledFingerprint.method
        val p1Reg = analyticsEnableMethod.implementation!!.registerCount - 1
        analyticsEnableMethod.addInstructions(
            0,
            if (p1Reg <= 15) {
                "const/4 p1, 0x0"
            } else {
                """
                    const/4 v0, 0x0
                    move/16 p1, v0
                """.trimIndent()
            },
        )

        for (params in firebaseVoidHookParamLists) {
            Fingerprint(
                definingClass = FIREBASE_ANALYTICS_CLASS,
                isStatic = false,
                parameters = params,
                returnType = "V",
            ).method.returnEarly()
        }

        for ((methodName, params) in appsFlyerVoidHooks) {
            Fingerprint(
                definingClass = RN_APPSFLYER_MODULE_CLASS,
                name = methodName,
                parameters = params,
                returnType = "V",
            ).method.returnEarly()
        }
    }
}
