# Upload videos from camera roll

Allows selecting and uploading videos from Android's system photo picker / gallery alongside photos using Locket's camera-roll button.

## How it works

Locket normally restricts `expo-image-picker` (`launchImageLibraryAsync`) to `MediaTypeOptions.Images` inside `useCameraRoll` and forwards every selected asset as `MediaTypes.cameraRollImage` (`HomeImageCrop`).

This patch applies three coordinated changes inside the Hermes bytecode bundle (`assets/index.android.bundle`):

1. **Allow videos in picker**: Rewrites `MediaTypeOptions.Images` to `MediaTypeOptions.All` in `useCameraRoll`'s module initializer.
2. **Preserve picked media type & raise pre-transcode limit**: Tags the picker callback payload with `fileType: asset.type` in-place inside `openCameraRoll`, and raises the pre-transcode file-size check from `100 MiB` to `512 MiB`.
3. **Route videos through native Media3 transcoding**: Relocates `Home`'s `useCameraRoll` `onSuccess` callback to route `fileType === 'video'` (with the `file://` URI scheme stripped cleanly to satisfy `VideoThumbnails.getThumbnailAsync`) into `Home`'s existing `onRecordingFinished` handler, running Locket's native Media3 `VideoTransformer.cropVideo` (720x720 center-cropped MP4), `HomeCapturedVideo` preview, overlays/captions, thumbnail generation, and Firebase Storage moment upload.

Picked images continue through the original `HomeImageCrop` path unchanged.

- Depends on **Unlock Gold** and signature spoofing so the `camera_roll` feature gate is unlocked on the Home screen.
- Enabled by default (`default = true`).
