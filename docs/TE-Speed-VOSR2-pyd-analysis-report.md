# TE-Speed-VOSR2 `.pyd` static analysis

## Scope and safety

This report records read-only static observations from:

```text
J:\mickeylan\ai\TE-Speed-VOSR2
```

The extension was not imported or executed. No model was loaded, no GPU code was run, and no target file was modified. Ghidra used ephemeral analysis databases.

This is compatibility-oriented behavior analysis, not recovery of original Python source.

## Package identity

The clear-text package entry point exports the ComfyUI mappings from `nodes.pyd`:

```python
from .nodes import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS
```

The included README identifies the package as a ComfyUI VOSR2 image/video super-resolution extension supporting image and frame-batch processing, manual/speed profiles, spatial and VAE tiling, optional DINO temporal caching, SageAttention fallback behavior, and optional `torch.compile`.

### Native modules

| Module            |   Bytes | SHA-256                                                            |  Names | Strings | Public detector                             |
| ----------------- | ------: | ------------------------------------------------------------------ | -----: | ------: | ------------------------------------------- |
| `nodes.pyd`       |  74,752 | `47125599d762690e2c17b103e146458f22f465daac38c789bfab658dfb4d4430` |  2,605 |     371 | Python extension confirmed; Cython unknown  |
| `settings.pyd`    |  46,592 | `f00a660c770afc7807dad606d73be338e028881f5c4c84e6714fd45b0ba24b86` |  1,690 |     295 | Python extension confirmed; Cython unknown  |
| `model_store.pyd` | 178,688 | `867ab66edfe872dc5c3f15ca7f105fb7eefbe4f9fd5b6ee34d5a6f84a8b8d3f9` |  5,611 |     681 | Python extension confirmed; Cython detected |
| `inference.pyd`   | 338,944 | `0a5e8db4de33a6c4afa088fdb4aac0e7d888870dcddbe78756b63ed6ddd2534b` | 10,190 |     728 | Python extension confirmed; Cython detected |

All four are x86-64 PE shared libraries. Their initializers are `PyInit_nodes`, `PyInit_settings`, `PyInit_model_store`, and `PyInit_inference`.

Although the conservative public detector reports Cython as unknown for `nodes` and `settings`, both inventories directly contain `_cython_3_1_2limitednofinalize` runtime names. This observation supports a Cython 3.1.2 limited-API build identity; it does not change the public detector result.

Embedded generated-C source paths point to:

```text
D:\ComfyUI_portable_TE_v260619\ComfyUI\custom_nodes\TE-Speed-VOSR2\yuan\_build_pyd\cython\nodes.c
D:\ComfyUI_portable_TE_v260619\ComfyUI\custom_nodes\TE-Speed-VOSR2\yuan\_build_pyd\cython\settings.c
D:\ComfyUI_portable_TE_v260619\ComfyUI\custom_nodes\TE-Speed-VOSR2\yuan\_build_pyd\cython\model_store.c
D:\ComfyUI_portable_TE_v260619\ComfyUI\custom_nodes\TE-Speed-VOSR2\yuan\_build_pyd\cython\inference.c
```

These paths are retained string observations, not available source files.

## ComfyUI node surface

`nodes.pyd` exposes these qualified method observations:

- `TESpeedVOSR2Loader.INPUT_TYPES`
- `TESpeedVOSR2Loader.load`
- `TESpeedVOSR2Settings.INPUT_TYPES`
- `TESpeedVOSR2Settings.make`
- `_VOSR2Base.INPUT_TYPES`
- `_VOSR2Base.upscale`
- `TESpeedVOSR2Video.INPUT_TYPES`
- `TESpeedVOSR2Video.upscale`

The string inventory also contains these class and display-name candidates:

| Class/key candidate    | Display-name candidate        |
| ---------------------- | ----------------------------- |
| `TESpeedVOSR2Loader`   | `TE-Speed VOSR2 Loader`       |
| `TESpeedVOSR2Settings` | `TE-Speed VOSR2 Settings`     |
| `TESpeedVOSR2Image`    | `TE-Speed VOSR2 Image`        |
| `TESpeedVOSR2Video`    | `TE-Speed VOSR2 Video Frames` |

The module initializer constructs these exact ComfyUI mappings:

```python
NODE_CLASS_MAPPINGS = {
    "TESpeedVOSR2Loader": TESpeedVOSR2Loader,
    "TESpeedVOSR2Settings": TESpeedVOSR2Settings,
    "TESpeedVOSR2Image": TESpeedVOSR2Image,
    "TESpeedVOSR2Video": TESpeedVOSR2Video,
}
NODE_DISPLAY_NAME_MAPPINGS = {
    "TESpeedVOSR2Loader": "TE-Speed VOSR2 Loader",
    "TESpeedVOSR2Settings": "TE-Speed VOSR2 Settings",
    "TESpeedVOSR2Image": "TE-Speed VOSR2 Image",
    "TESpeedVOSR2Video": "TE-Speed VOSR2 Video Frames",
}
```

All four nodes use `CATEGORY = "TE-Speed/VOSR2"`. Their remaining class contracts are:

| Class                  | `RETURN_TYPES`                 | `RETURN_NAMES`  | `FUNCTION`  |
| ---------------------- | ------------------------------ | --------------- | ----------- |
| `TESpeedVOSR2Loader`   | `("TE_SPEED_VOSR2_MODEL",)`    | `("model",)`    | `"load"`    |
| `TESpeedVOSR2Settings` | `("TE_SPEED_VOSR2_SETTINGS",)` | `("settings",)` | `"make"`    |
| `TESpeedVOSR2Image`    | `("IMAGE",)`                   | `("image",)`    | `"upscale"` |
| `TESpeedVOSR2Video`    | `("IMAGE",)`                   | `("image",)`    | `"upscale"` |

### Exact `INPUT_TYPES` schemas

The 119-entry Cython string table begins at `0x18000f510` and populates globals from `0x1800138c8`. Decoding those globals in the owning method bodies establishes the following dictionaries.

`TESpeedVOSR2Loader.INPUT_TYPES()` returns:

```python
{
    "required": {
        "model_bundle": (bundle_names(), {"default": DEFAULT_BUNDLE}),
        "precision": (["auto", "fp16", "bf16"], {"default": "auto"}),
        "memory_policy": (["auto", "resident", "staged"], {"default": "auto"}),
    },
    "optional": {
        "torch_compile": ("BOOLEAN", {"default": False}),
        "vae_encode_amp": ("BOOLEAN", {"default": False}),
    },
}
```

`TESpeedVOSR2Settings.INPUT_TYPES()` returns one `required` group:

| Field              | Type/choices                  |   Default | Minimum | Maximum |   Step |
| ------------------ | ----------------------------- | --------: | ------: | ------: | -----: |
| `quality_profile`  | `manual`, `speed`             |   `speed` |       — |       — |      — |
| `tile_strategy`    | `auto`, `full_frame`, `tiled` |    `auto` |       — |       — |      — |
| `tile_size`        | `INT`                         |       512 |     128 |    4096 |     64 |
| `tile_overlap`     | `INT`                         |        32 |       0 |     512 |      8 |
| `vae_tile_size`    | `INT`                         |      1024 |       0 |    8192 |     64 |
| `vae_tile_overlap` | `INT`                         |        32 |       0 |     512 |      8 |
| `image_batch`      | `INT`                         |         1 |       1 |      32 |      — |
| `frame_batch`      | `INT`                         |         2 |       1 |       8 |      — |
| `dino_batch`       | `INT`                         |         2 |       1 |       8 |      — |
| `temporal_cache`   | `BOOLEAN`                     |   `False` |       — |       — |      — |
| `cache_threshold`  | `FLOAT`                       |     0.003 |     0.0 |    0.25 | 0.0005 |
| `cache_refresh`    | `INT`                         |         4 |       1 |      32 |      — |
| `memory_policy`    | `auto`, `resident`, `staged`  |    `auto` |       — |       — |      — |
| `color_alignment`  | `wavelet`, `adain`, `none`    | `wavelet` |       — |       — |      — |

`_VOSR2Base.INPUT_TYPES()` returns:

```python
{
    "required": {
        "model": ("TE_SPEED_VOSR2_MODEL",),
        "images": ("IMAGE",),
        "scale": ("INT", {"default": 2, "min": 1, "max": 16}),
        "seed": ("INT", {"default": 42, "min": 0, "max": 0xffffffffffffffff}),
    },
    "optional": {
        "settings": ("TE_SPEED_VOSR2_SETTINGS",),
    },
}
```

`TESpeedVOSR2Video.INPUT_TYPES()` first obtains the base-class dictionary, then mutates its `optional` group with:

| Field             | Type      | Default | Minimum | Maximum |   Step |
| ----------------- | --------- | ------: | ------: | ------: | -----: |
| `frame_batch`     | `INT`     |       0 |       0 |       8 |      — |
| `temporal_cache`  | `BOOLEAN` | `False` |       — |       — |      — |
| `cache_threshold` | `FLOAT`   |   0.003 |     0.0 |    0.25 | 0.0005 |
| `cache_refresh`   | `INT`     |       4 |       1 |      32 |      — |

The video node therefore preserves the same required `model`, `images`, `scale`, and `seed` inputs as `_VOSR2Base`; its optional values override or supplement settings at call time. No target execution was used to obtain these values.

### Located wrapper/body boundaries

| Method                             | Wrapper                    | Body / current observation           |
| ---------------------------------- | -------------------------- | ------------------------------------ |
| `TESpeedVOSR2Loader.INPUT_TYPES`   | `0x180001000`, 630 bytes   | `FUN_180001280`, 1,968 bytes         |
| `TESpeedVOSR2Settings.INPUT_TYPES` | `0x180002370`, 630 bytes   | `FUN_1800025f0`, 4,945 bytes         |
| `_VOSR2Base.INPUT_TYPES`           | `0x180003dd0`, 1,639 bytes | body relationship not yet separated  |
| `_VOSR2Base.upscale`               | `0x180004440`, 1,841 bytes | implementation target not yet proven |
| `TESpeedVOSR2Video.INPUT_TYPES`    | `0x180004b90`, 630 bytes   | `FUN_180004e10`, 1,960 bytes         |
| `TESpeedVOSR2Video.upscale`        | `0x1800055c0`, 2,009 bytes | `FUN_180005de0`, 2,625 bytes         |

The wrappers expose ordinary Cython argument-count/type errors. They do not by themselves prove Python signatures or keyword-only status.

## Settings model

`settings.pyd` exposes `settings.VOSR2Settings.normalized`. The settings inventory contains the same profile, tiling, cache, precision, and batching vocabulary listed above. Exact dataclass/constructor fields, normalization defaults, clamping behavior, and validation exceptions remain to be decoded.

## Model store surface

`model_store.pyd` exposes:

- `bundle_names` and its generator
- `_bundle_path`
- `_find_dit`
- `_find_dino`
- `_dtype`
- `_load_state`
- `_strict`
- `TESpeedVOSR2Model.__init__`
- `set_torch_compile`
- `set_memory_policy`
- `_patchers`
- `pin_resident`
- `_load`
- `_load_stage`
- `_dino_norm`
- `dino_features`
- `_autocast_if`
- `_vae_autocast`
- `encode`
- `decode`
- `velocity`
- `one_step`
- `clear_staged`
- `_unload_transformers`
- `_transformer_bytes`
- `prepare_vae_decode`
- `load_model`

Direct dependency/name observations include:

```text
comfy.model_management
comfy.model_patcher
comfy.utils
safetensors.torch
backend.models.lightningdit
backend.models.qwenimage_vae2d
backend.models.dinov2
args.json
ema_model.safetensors
dinov2_vitl14.safetensors
dinov2_vitl14_pretrain.pth
```

This supports a model bundle containing LightningDiT, Qwen Image VAE 2D, and DINOv2 components managed through ComfyUI primitives. Exact constructor parameters, state-dict policies, device movement, cache identity, and unload ordering remain Unknown.

## Inference surface

`inference.pyd` exposes `run_vosr2` plus these helpers:

```text
_pad_multiple
_latent_side
_pad_square
_noise
_tile_positions
_restored_tile_weight
_signature
_cache_hit
_reuse_flags
_split_feature_batch
_cpu_store
_to_device
_keep_on_gpu
_merge_cached_features
_PhaseClock.__init__
_PhaseClock.phase
_PhaseClock.flush
_Phase.__init__
_Phase.__enter__
_Phase.__exit__
_timed
_flush
_prepare_vae_decode
_ensure_speed_runtime
_enable_fast_math
_vae_tile_for_profile
_vae_tile_count
_color_downsample
_dit_tile_batch
_upsample_batch
_finish_batch
_fallback_vae_tile
_run_dit_tiles
_tile_geometry
_dino_tiles
_full_frame
_encode_resized
_decode_restored
_phased_tiled
_streaming_tiled
run_vosr2
```

Direct dependency/name observations include `torch.nn.functional`, `comfy.model_management`, `comfy.utils`, `backend.color`, and `backend.models.lightningdit`.

The function names structurally support full-frame and tiled routes, phase timing, DINO feature caching, device/CPU movement, VAE fallback tiling, and final batch assembly. They do not yet prove exact algorithms, tensor layouts, numeric constants, error handling, or profile-selection conditions.

## README-derived behavior

The bundled README states that version 1.0 supports:

- VOSR 2.0 1.4B one-step models;
- image restoration and integer scaling;
- video `IMAGE` frame batches;
- `manual` and `speed` configurations;
- spatial and VAE tiling;
- optional video DINO temporal caching;
- ComfyUI SageAttention with SDPA fallback;
- optional `torch.compile` with eager fallback.

It specifies this model layout:

```text
ComfyUI/models/vosr2/VOSR2/
|-- args.json
|-- checkpoints/
|   `-- ema_model.safetensors
|-- Qwen-Image-vae-2d/
|   |-- config.json
|   `-- diffusion_pytorch_model.safetensors
`-- dinov2_vitl14.safetensors
```

It also states that `dinov2_vitl14_pretrain.pth` is accepted. These are package-document observations, not runtime verification.

## Next analysis steps

1. Recover `load`, `make`, image `upscale`, and video `upscale` calling conventions and return paths.
2. Recover `VOSR2Settings.normalized` rules.
3. Decode the remaining `model_store` and `inference` global tables.
4. Trace `load_model` and `TESpeedVOSR2Model` cache/device lifecycle.
5. Trace `run_vosr2` route selection and exact cleanup/error behavior.

## Evidence identifiers

- `nodes.pyd`: `ev_c94195175c246b11a0b0e0bfef55f5aa7d4bf686526fb218f91e15bb992eec85`
- `settings.pyd`: `ev_efb86b94a29e29830e3725534a4345d3478444bbb19c56466f2af13de6e02a51`
- `model_store.pyd`: `ev_f74f95d36c8116af4a7763803cd348d4feae1075987a7a21666fb61a07ea60dc`
- `inference.pyd`: `ev_53e1cb013a0c53acab344149820c832998fd32511024a1e46a8ec685357c77a8`
