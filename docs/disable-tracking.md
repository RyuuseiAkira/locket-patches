# Disable tracking and analytics

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`)
- **Runtime:** Hermes HBC v96 (`assets/index.android.bundle`) + Dalvik bytecode (`classes*.dex`)

## Mechanism

1. **Remote config telemetry & Sentry sampling (`HermesHbc96`):**
   - Sets `androidReadopsAmplitudeLogging`, `androidSendDebugInfo`, `sentryPerformanceTracking`, `sentrySessionTracking`, and `sentryTombstone` to `false`.
   - Sets `sentrySampleRate`, `sentryTracesSampleRate`, and `sentryProfilesSampleRate` to `0` (`LoadConstZero`).
2. **JS attribution & analytics dispatchers (`HermesHbc96`):**
   - Early returns `undefined` from `initAppsFlyer`, `logAppsFlyerEvent`, `logEventToAppsFlyer`, `enableAdServicesAttributionTokenCollection`, `initAmplitudeFlags`, `logEventToAmplitudeIfEnabled`, and `setNativeTelemetryEnabled`.
3. **Native SDK hooks (Dalvik):**
   - `CameraDebugModule.setTelemetryEnabled(Z)Z` -> returns `false`.
   - `FirebaseAnalytics` (`c/d/g/h/i/j/setCurrentScreen` matched by unique parameter descriptors) -> returns early (`return-void`), while `setAnalyticsCollectionEnabled(Z)` (`e(Z)V`) forces argument `p1 = 0` (`false`).
   - `RNAppsFlyerModule` void entry points (`startSdk`, `performOnDeepLinking`, `logAdRevenue`, `logCrossPromotionImpression`, `setConsentData`, `initSdkWithCallBack`, `logEvent`) -> return early (`return-void`).
