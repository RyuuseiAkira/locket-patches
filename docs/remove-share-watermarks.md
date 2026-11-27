# Remove share watermarks

## Target

- **App:** Locket Widget (`com.locket.Locket`)
- **Confirmed version:** `1.247.1` (version code `632`)
- **Runtime:** Dalvik bytecode (`com.jimmydaddy.imagemarker`)

## Mechanism

Opt-in (`default = false`) native overlay removal for shared History and Moment exports:

1. Matches `Lcom/jimmydaddy/imagemarker/a;` by `"Watermark bitmap at index "` and resolves its unique zero-parameter array getter (`[L...;`, obfuscated as `Ldf/d;->f()[Ldf/t;` in `1.247.1`).
2. Rewrites that getter's entry point to return a zero-length array (`const/4 v0, 0x0; new-array v0, v0, [Ldf/t;; return-object v0`).

Both `ImageMarkerManager` Glide overlay preloading and `a->a(...)` Canvas compositing skip watermark overlays cleanly while preserving background decoding, scaling, rotation, quality compression, `markWithText`, and cache URI Promise resolution.
