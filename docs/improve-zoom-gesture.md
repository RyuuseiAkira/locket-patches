# Improve Zoom Gesture

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`, universal `.apkm`)
- **Runtime:** React Native Hermes bytecode (`assets/index.android.bundle`, HBC v96) & Reanimated UI Worklets (`libworklets.so`)

## Problem

Locket's pinch-to-zoom handler (`HomeCameraTsx3`) uses two chained linear `interpolate(..., Extrapolation.CLAMP)` calls with `SCALE_FULL_ZOOM = 3`:
- Shrinking fingers slightly (`event.scale = 0.667`) immediately dumps zoom down to `minZoom` (`0.5x`), making zoom-out abrupt and overly sensitive.
- Spreading fingers linearly interpolates `[pinchStartZoom.value, maxZoom]` across `[1, 3]`, requiring an impractical `3x` finger spread inside the square viewfinder while jumping too rapidly on high-`maxZoom` Android cameras.

## Mechanism

1. **Worklet `__initData.code` synthesis (`HomeCameraTsx3Factory`):**
   Reanimated evaluates `worklet.__initData.code` on the UI worklet runtime via `evalWithSourceUrl`. Because Hermes substring-deduplicates identifiers (`maxZoom`, `minZoom`, `pinchStartZoom`, `SCALE_FULL_ZOOM`) inside the original worklet string in string storage, `HomeCameraTsx3Factory` is patched via bytecode relocation instead of overwriting string storage in place. Before assigning `worklet.__initData`, a relocated tail synthesizes a fresh `{ code }` object keeping the `__closure` header and replacing the body with:
   ```js
   zoom.set(Math.min(maxZoom,Math.max(minZoom,pinchStartZoom.value*Math.pow(Math.max(0.01,event.scale),1.8))));
   ```
2. **Fallback JS closure (`HomeCameraTsx3`):**
   Resolves closure environment slot indices dynamically from `HomeCameraTsx3Factory` and rewrites `HomeCameraTsx3` HBC v96 bytecode to match the same multiplicative power curve and clamping, updating header bounds and trailing SHA-1 integrity.
