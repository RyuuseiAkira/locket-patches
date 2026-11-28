# Default back camera

Starts Locket's main viewfinder camera on the rear (`back`) lens instead of the front selfie lens.

## How it works

Locket's `Home` component initializes its camera state via `useState('front')` before resolving `useCameraDevice(cameraPosition)` and `backFacing`.

This patch updates only that initial `useState('front')` string literal operand in `Home` to `'back'` inside the Hermes bytecode bundle (`assets/index.android.bundle`).

- The camera flip button (`front` <-> `back`) still works normally.
- Dual Camera and QR Scanner (`back`) behavior is preserved.
- Opt-in (`default = false`).
