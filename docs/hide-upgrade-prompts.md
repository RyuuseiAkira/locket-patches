# Hide upgrade and invite prompts

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`)
- **Runtime:** Hermes HBC v96 (`assets/index.android.bundle`)

## Mechanism

Opt-in (`default = false`) cleanup of upsell and referral UI gates:

- `androidSubscribeGoldButtonEnabled` -> `false`
- `getFeatureDiscoveryPopupConfig` -> `null`
- `settingsUpsellFeatures` -> `{}` (`NewObject r0; Ret r0`)
- `rewardedReferralsConfig` -> `null`
- `linkReferralsEnabled` -> `false`
- `isEligibleForRewardedReferralsPopup` -> `false`
