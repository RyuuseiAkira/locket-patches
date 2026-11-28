# GmsCore support

Enables Google Sign-In and Play Services features on patched non-root Locket Widget builds using **MicroG-RE** (`app.revanced.android.gms`).

## Requirements

- Install **MicroG-RE** (`app.revanced.android.gms`, [MorpheApp/MicroG-RE](https://github.com/MorpheApp/MicroG-RE/releases/latest)) alongside your patched Locket APK.
- Sign in to your Google account in MicroG-RE and exclude MicroG-RE from aggressive battery optimizations if push notifications are delayed.
- On Android 14+, make sure MicroG Services is enabled under system Passwords, passkeys & accounts settings if Google one-tap / Credential Manager prompts do not appear automatically.

## What it patches

- Rewrites Google Play Services, Google Auth / Identity / Credential Manager, Phenotype, GServices, and C2DM/FCM IPC strings (`com.google` / `com.google.android.gms` / `com.google.android.c2dm`) to `app.revanced.*`.
- Bypasses `GooglePlayServicesUtilLight` availability and `UidVerifier.isGooglePlayServicesUid` Google signing-certificate checks (while keeping `AppOpsManager` UID package ownership enforcement intact).
- Applies Morphe's `spoofSignaturePatch` (`app.morphe.ORIGINAL_SIGNATURE`) and `gmsCorePackageQueriesPatch` (`<queries>` visibility for `app.revanced.android.gms`).
- Adds `app.revanced.android.gms.SPOOFED_PACKAGE_NAME` (`com.locket.Locket`), `app.revanced.android.gms.SPOOFED_PACKAGE_SIGNATURE` (leaf certificate SHA-1 extracted dynamically from the original APK), and `app.revanced.MICROG_PACKAGE_NAME` metadata to `AndroidManifest.xml`.
- Unavailable for root `MOUNT` installs (which retain the original signature and stock Google Play Services).
