# Remove ads

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`)
- **Runtime:** React Native Hermes bytecode (`assets/index.android.bundle`, HBC v96)

## Mechanism

Rewrites client-side ad configuration and eligibility checks in `assets/index.android.bundle` via [`HermesHbc96`](../patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/HermesHbc96.kt):

1. `androidHistoryAdsEnabled` (`getBoolean("android_history_ads_enabled")`) -> `LoadConstFalse; Ret; Unreachable` (`false`)
2. `androidHistoryAdsReportingEnabled` (`getBoolean("android_history_ads_reporting_enabled")`) -> `LoadConstFalse; Ret; Unreachable` (`false`)
3. `isUserEligibleForAds` (`historyAdsEarliestLegalNoticeDate`) -> early return `LoadConstFalse r0; Ret r0` (`false`)

Depends on `spoofSignaturePatch` so Firebase Auth and Remote Config stay functional on re-signed builds.
