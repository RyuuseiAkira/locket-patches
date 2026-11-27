# Enable Telephoto Zoom Toggle

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`, universal `.apkm`)
- **Runtime:** React Native Hermes bytecode (`assets/index.android.bundle`, HBC v96) & VisionCamera 5 (Nitro)

## Problem

- Locket's viewfinder zoom pill (`CameraOverlayZoomButton`) and `getNextZoomValue` only toggle between `minZoom` (`0.5x`) and `neutralZoom` (`1x`).
- Devices that lack a wide `0.5x` lens (`minZoom >= neutralZoom`) hide the pill completely even when a telephoto camera is available, and devices with a telephoto lens cannot tap the pill to switch to `3x`.
- On Android, VisionCamera's `device.zoomLensSwitchFactors` returns an empty array (`double[0]`), whereas `device.type` and `device.physicalDevices[].type` report `"telephoto"` for physical telephoto sensors (`intrinsicZoomRatio > 1.0f`).

## Mechanism

Rewrites and cleanly relocates four coordinated HBC v96 functions before `debugInfoOffset`, updating headers, `fileLength`, and trailing SHA-1 integrity:

1. **`Home` (`lensSwitch` detection & visibility):**
   For back-facing cameras with `zoomProps.maxZoom >= 3`, checks `device.type === "telephoto"` or any element of `device.physicalDevices` with `.type === "telephoto"`. Keeps `<CameraZoomOverlay>` visible whenever `minZoom < neutralZoom || telephotoAvailable`, and passes `lensSwitch` via `overlayZoomButtonProps`.
2. **`CameraOverlayZoomButton` (React Compiler memo cache expansion):**
   Expands cache size `c(12)` to `c(13)`, captures `props.lensSwitch` into the closure environment, and keys the cached `onPress` closure on slot `12` (`lensSwitch`) so switching cameras updates the toggle behavior.
3. **Toggle `onPress` closure:**
   Forwards `lensSwitch` as the 4th argument to `getNextZoomValue` using `Call`.
4. **`getNextZoomValue(neutralZoom, currentZoom, minZoom, telephotoEnabled)`:**
   - When `telephotoEnabled` is truthy and `minZoom < neutralZoom`: cycles `0.5x -> 1x -> 3x -> 0.5x`.
   - When `telephotoEnabled` is truthy and `minZoom >= neutralZoom`: toggles `1x <-> 3x`.
   - When `telephotoEnabled` is falsy (non-telephoto or front camera): preserves original `0.5x <-> 1x` switching.
   - `CameraOverlayZoomButton`'s existing `formatDisplay` formatter renders `3` as `3×`.
