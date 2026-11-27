# Bypass forced updates

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`)
- **Runtime:** Hermes HBC v96 (`assets/index.android.bundle`) + Dalvik bytecode (`AppUpdateModule`)

## Mechanism

1. **Remote config update prompt coroutine (`?anon_0_` with `forceUpgradeVersionPattern` + `recommendUpgradeVersionPattern`):**
   Patches right after `StartGenerator; ResumeGenerator; JmpTrueLong` to return `undefined` (`LoadConstUndefined r1; CompleteGenerator; Ret r1`). Patching the coroutine directly prevents an empty `""` pattern from matching any version via `new RegExp("")`.
2. **Native Play In-App Updates (`Lcom/locket/Locket/AppUpdateModule;->startUpdate(I)V`):**
   Prepends `return-void` (`returnEarly()`).
3. **Automatic Play Store review prompts (`_shouldPromptForReview` & auto-review generator):**
   Patches `?anon_0_` (`currentUser`, `getNumSentLockets`) to resolve `false` and `?anon_0_` (`logPromptedForStoreReview`, `requestReview`) to resolve `undefined`, without breaking explicit in-app Settings review buttons.
