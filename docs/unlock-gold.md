# Unlock Gold

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`, universal `.apkm`)
- **Runtime:** React Native Hermes bytecode (`assets/index.android.bundle`, HBC v96)

## Mechanism

1. **Signature spoofing (`spoofSignaturePatch`):**
   Locket's Firebase Auth, Firebase Remote Config, and Play Services clients inspect `PackageManager.getPackageInfo` / `SigningInfo` to populate `X-Android-Package` and `X-Android-Cert`. Depending on `spoofSignaturePatch` preserves the original Play Store certificate hash so login and remote config requests continue working after re-signing.

2. **Hermes HBC v96 bytecode override (`HermesHbc96`):**
   - Verifies the `0x1f1903c103bc1fc6` HBC magic, version `96`, `fileLength`, and trailing 20-byte SHA-1 digest.
   - Resolves `"androidGoldSubscriptionOverride"`, `"getBoolean"`, and `"android_gold_subscription_override"` dynamically from the bundle string table (`SmallStringTableEntry` + `OverflowStringTableEntry`).
   - Locates `androidGoldSubscriptionOverride` via `SmallFuncHeader` / `LargeFuncHeader` and matches the contiguous sequence:
     - `GetById <rFn>, <rObj>, <cacheIdx>, "getBoolean"` (`0x37`)
     - `LoadConstString` (`0x73`) or `LoadConstStringLongIndex` (`0x74`) for `"android_gold_subscription_override"` -> `<rArg>`
     - `Call2 <rDst>, <rFn>, <rObj>, <rArg>` (`0x53`, 5 bytes)
     - `Ret <rDst>` (`0x5c`, 2 bytes)
   - Replaces the 5-byte `Call2` instruction in place with:
     - `LoadConstTrue <rDst>` (`0x78 <rDst>`)
     - `Ret <rDst>` (`0x5c <rDst>`)
     - `Unreachable` (`0x00`)
   - Recomputes the trailing 20-byte SHA-1 footer over `bytes[0 .. size - 20)`.
   - Morphe's resource packager keeps `assets/index.android.bundle` uncompressed (`STORED`) to match the original APK.

## Client / Server Scope

- **Client-side unlocked:** Local subscription override gate (`androidGoldSubscriptionOverride`) and Gold UI/client features controlled by that override.
- **Server-controlled:** Backend entitlement validation, receipt verification, and server-enforced API limits remain governed by Locket's servers.
