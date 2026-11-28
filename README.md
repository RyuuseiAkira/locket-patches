# 🧩 Locket Patches

Morphe patches for **Locket Widget** (`com.locket.Locket`).

## ➕ Add to Morphe

**One tap** (open on the phone that runs Morphe Manager):
[**Add to Morphe**](https://morphe.software/add-source?github=RyuuseiAkira/locket-patches)

**Manually:** Morphe Manager → patch sources **+** → **Remote** → paste
`https://github.com/RyuuseiAkira/locket-patches`

Uninstall the Play Store version of Locket Widget first. The patched build is signed with a different key.
Provide an unmodified APK / APKM (such as `com.locket.Locket` `1.247.1`).

> GPLv3 · Not affiliated with Locket Labs. Targets the Locket Widget versions in the patch list below.
> **Unlock Gold** depends on `spoofSignaturePatch` (`PackageManager` signature spoofing) so Firebase Auth,
> Remote Config, and App Check still pass original-certificate checks on re-signed builds.
> Server-enforced entitlements, backend payment receipts, and server-side subscription checks stay controlled
> by Locket's servers; client-side Gold gates driven by `android_gold_subscription_override` are unlocked locally.

## 🩹 Patches

<!-- PATCHES_START EXPANDED -->
> **[v1.0.0](https://github.com/RyuuseiAkira/locket-patches/releases/tag/v1.0.0)**&nbsp;&nbsp;&middot;&nbsp;&nbsp;`main`&nbsp;&nbsp;&middot;&nbsp;&nbsp;**6 patches** across **1 app**&nbsp;&nbsp;&middot;&nbsp;&nbsp;[Full details](PATCHES.md)

| # | App | Patches | Version | Package |
|---|---|---|---|---|
| 1 | [**Locket Widget**](PATCHES.md#locket-widget-comlocketlocket) | 6 | `1.247.1` | [`com.locket.Locket`](https://play.google.com/store/apps/details?id=com.locket.Locket) |
<!-- PATCHES_END -->

## 📚 Documentation

Technical notes, Hermes bytecode patching layout, and client/server scope live in [`docs/`](docs/):

- [Unlock Gold & Hermes HBC v96 patching](docs/unlock-gold.md)
- [Remove ads](docs/remove-ads.md)
- [Bypass forced updates](docs/bypass-forced-updates.md)
- [Disable tracking and analytics](docs/disable-tracking.md)
- [Hide upgrade and invite prompts](docs/hide-upgrade-prompts.md)
- [Remove share watermarks](docs/remove-share-watermarks.md)
- [Default back camera](docs/default-back-camera.md)
- [GmsCore support (MicroG-RE)](docs/gmscore-support.md)

## 🛠️ Building locally

- `./gradlew buildAndroid` → the bundle lands in `patches/build/libs/patches-*.mpp`
- Patch that file with [Morphe Desktop](https://github.com/MorpheApp/morphe-desktop) like any other bundle.
- Requires JDK 17+ and GitHub Packages `read:packages` credentials (`gpr.user`/`gpr.key` or `GITHUB_ACTOR`/`GITHUB_TOKEN`) to resolve `app.morphe:*` dependencies.

## 📜 License

[GNU General Public License v3.0](LICENSE).

## 🙏 Credits

- Built with [MorpheApp/morphe-patches-template](https://github.com/MorpheApp/morphe-patches-template), [MorpheApp/morphe-patcher](https://github.com/MorpheApp/morphe-patcher), and [MorpheApp/morphe-patches-library](https://github.com/MorpheApp/morphe-patches-library) (GPLv3).
