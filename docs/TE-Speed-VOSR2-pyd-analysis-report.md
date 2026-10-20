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

| Method                             | Wrapper                    | Body / current observation   |
| ---------------------------------- | -------------------------- | ---------------------------- |
| `TESpeedVOSR2Loader.INPUT_TYPES`   | `0x180001000`, 630 bytes   | `FUN_180001280`, 1,968 bytes |
| `TESpeedVOSR2Settings.INPUT_TYPES` | `0x180002370`, 630 bytes   | `FUN_1800025f0`, 4,945 bytes |
| `_VOSR2Base.INPUT_TYPES`           | `0x180003dd0`, 1,639 bytes | implementation is inline     |
| `_VOSR2Base.upscale`               | `0x180004440`, 1,841 bytes | implementation is inline     |
| `TESpeedVOSR2Video.INPUT_TYPES`    | `0x180004b90`, 630 bytes   | `FUN_180004e10`, 1,960 bytes |
| `TESpeedVOSR2Video.upscale`        | `0x1800055c0`, 2,009 bytes | `FUN_180005de0`, 2,625 bytes |

### Public method calling conventions and returns

The decoded wrapper parameter tables establish these Python call shapes:

```python
TESpeedVOSR2Loader.load(
    self,
    model_bundle,
    precision,
    memory_policy,
    torch_compile=False,
    vae_encode_amp=False,
)

TESpeedVOSR2Settings.make(self, **settings)

_VOSR2Base.upscale(
    self,
    model,
    images,
    scale,
    seed,
    settings=None,
)

TESpeedVOSR2Video.upscale(
    self,
    model,
    images,
    scale,
    seed,
    settings=None,
    frame_batch=0,
    temporal_cache=False,
    cache_threshold=0.003,
    cache_refresh=4,
)
```

Arguments may be populated positionally or by keyword according to the ordinary Cython parser; these parameters are not keyword-only. The first three non-`self` loader arguments and first four non-`self` upscale arguments are required. Unknown or duplicate keywords raise the generated `TypeError` path.

`load` performs the equivalent observed sequence:

1. `model = load_model(model_bundle, precision)`;
2. assign `model.memory_policy = memory_policy`;
3. normalize `vae_encode_amp` through Python truth testing and assign the resulting `bool` to `model.vae_encode_amp`;
4. normalize `torch_compile` through Python truth testing;
5. resolve `_bundle_path(model_bundle)`;
6. invoke `model.set_torch_compile(normalized_torch_compile, resolved_bundle_path)`;
7. return `(model,)`.

`make` copies the collected keyword dictionary, constructs `VOSR2Settings(**settings)`, calls `.normalized()`, and returns `(normalized_settings,)`.

The base image `upscale` treats a falsey `settings` value as absent and constructs `VOSR2Settings()` in that case. It then invokes:

```python
run_vosr2(model, images, scale, seed, effective_settings)
```

and returns `(result,)`.

The video `upscale` similarly supplies default settings when needed. For a supplied settings object it copies `settings.__dict__`, applies its explicit video overrides, reconstructs `VOSR2Settings(**copied_values)`, and calls `.normalized()`. A positive `frame_batch` overrides the normalized setting; `0` selects `normalized.frame_batch`. Its `run_vosr2` keyword dictionary includes:

```python
{
    "batch_override": effective_frame_batch,
    "temporal_cache": normalized.temporal_cache,
    "auto_expand_vae_tile": True,
}
```

along with the common model/image/scale/seed/settings inputs. It returns `(result,)`. The exact remaining keyword set and override precedence are still being traced.

Every helper failure propagates through the generated exception path and returns native `NULL`; none of these wrappers converts a failure into an empty image or `None` success value.

## Settings model

`settings.pyd` exposes `settings.VOSR2Settings.normalized`. The wrapper accepts only `self`; unexpected keywords and extra positional arguments use the ordinary generated `TypeError` paths.

The body constructs and returns a new `VOSR2Settings` rather than mutating `self`. Its recovered normalization rules are:

```python
profile_aliases = {
    "detail": "manual",
    "balanced": "manual",
    "throughput": "speed",
}
quality_profile = profile_aliases.get(self.quality_profile, self.quality_profile)
if quality_profile not in ("manual", "speed"):
    quality_profile = "manual"

if self.tile_strategy not in ("auto", "full_frame", "tiled"):
    tile_strategy = "auto"
else:
    tile_strategy = self.tile_strategy

if self.memory_policy not in ("auto", "resident", "staged"):
    memory_policy = "auto"
else:
    memory_policy = self.memory_policy

tile_size = max(128, int(self.tile_size))
tile_overlap = max(0, min(int(self.tile_overlap), tile_size - 1))
vae_tile_size = max(0, int(self.vae_tile_size))
if vae_tile_size:
    vae_tile_overlap = max(
        0,
        min(int(self.vae_tile_overlap), max(1, vae_tile_size - 1)),
    )
else:
    vae_tile_overlap = 0

image_batch = max(1, int(self.image_batch))
frame_batch = max(1, int(self.frame_batch))
dino_batch = max(1, int(self.dino_batch))
temporal_cache = bool(self.temporal_cache)
cache_threshold = max(0.0, float(self.cache_threshold))
cache_refresh = max(1, int(self.cache_refresh))
```

The body forwards `color_alignment` into the reconstructed settings object. It also forwards the normalized fields above through one 14-argument constructor call. Exact constructor-field ordering for the remaining boolean/configuration fields is still being mapped, but the value transformations shown above are structurally explicit.

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

This supports a model bundle containing LightningDiT, Qwen Image VAE 2D, and DINOv2 components managed through ComfyUI primitives.

### Loading and model construction

The public loader is exactly:

```python
load_model(bundle_name: str, dtype_name: str)
```

It resolves `_bundle_path(bundle_name)`, requires the result to be a directory, opens `args.json` in text mode with UTF-8 encoding, and parses it with `json.load`. The statically observed required architecture-key set includes:

```text
dim
depth
num_heads
patch_size
enc_dim
layer_dinov2b_list
```

### DiT construction

`compute_dtype` is resolved first by `_dtype(dtype_name, load_device)`:

```python
if dtype_name == "fp16":
    compute_dtype = torch.float16
elif dtype_name == "bf16":
    compute_dtype = torch.bfloat16
else:
    compute_dtype = comfy.model_management.unet_dtype(device=load_device)
```

Thus only the exact strings `"fp16"` and `"bf16"` force a dtype. `"auto"` and every other Unicode value use ComfyUI's device-aware `unet_dtype`; unknown names are not rejected at this helper boundary. Both `value` and `device` are required arguments.

`LightningDiT` is then constructed entirely with keyword arguments:

```python
LightningDiT(
    input_size=args["resolution"] // 8,
    patch_size=args["patch_size"],
    in_channels=32,
    out_channels=16,
    hidden_size=args["dim"],
    depth=args["depth"],
    num_heads=args["num_heads"],
    mlp_ratio=args["mlp_ratio"],
    z_dims=args["enc_dim"],
    encdim_ratio=args["encdim_ratio"],
    auxiliary_time_cond=args.get("auxiliary_time_cond", False),
    use_qknorm=args["use_qknorm"],
    use_swiglu=args["use_swiglu"],
    use_rope=args["use_rope"],
    use_rmsnorm=args["use_rmsnorm"],
    num_fused_layers=len(args.get("layer_dinov2b_list", [17])),
)
```

Although the early explicit required-field check is narrower, subsequent direct dictionary indexing makes `resolution`, `mlp_ratio`, `encdim_ratio`, and the four `use_*` fields effectively required as well; absence propagates the dictionary lookup exception.

The resulting DiT follows this order:

```python
dit_path = _find_dit(bundle)
dit_state = _load_state(dit_path)
_strict(dit_model, dit_state, dit_path)
dit_model = dit_model.eval()
dit_model.to(compute_dtype)
```

As with DINO, this `to(...)` call supplies the dtype but no explicit device; `ModelPatcher` owns later device placement.

After constructing `LightningDiT`, it locates per-component weights through bound helpers:

- `_find_dit(bundle)` checks these paths in order:
  1. `bundle/checkpoints/ema_model.safetensors`;
  2. `bundle/clean_weights/ema_model.safetensors`;
  3. `bundle/ema_model.safetensors`.
     If none is a file, it raises `VOSR2LoadError("Missing VOSR2 DiT weight under " + str(bundle))`.
- `_find_dino(bundle)` checks these bundle-root paths in order:
  1. `bundle/dinov2_vitl14.safetensors`;
  2. `bundle/dinov2_vitl14_pretrain.pth`.
     It returns the first existing file. Failure raises `VOSR2LoadError` beginning `Missing DINOv2 weight under ` and includes both expected names.

`_load_state(path)` dispatches by `path.suffix`:

- `.safetensors` uses `safetensors.torch.load_file(str(path))`;
- every other suffix uses `comfy.utils.load_torch_file(path, safe_load=True)`.

The result must be a mapping whose retained values are `torch.Tensor` instances; otherwise it raises `VOSR2LoadError("Expected a state dict in " + str(path))`. This boundary therefore does not directly call `torch.load` and does not limit the non-safetensors branch to only `.pth` or `.pt`.

`_strict(module, state, path)` creates a cleaned state dictionary before loading:

- it strips the first matching prefix from `module.`, `_orig_mod.`, and `ema_model.`;
- it drops bookkeeping keys `n_averaged`, `step_count`, and `decay`;
- it calls `module.load_state_dict(cleaned_state, strict=False)` and unpacks `(missing, unexpected)`.

If either result is non-empty, it raises `VOSR2LoadError` with:

```text
Checkpoint mismatch for <module-name>: missing=<missing>, unexpected=<unexpected>
```

Using `strict=False` internally is deliberate: compatibility is still strict at the helper boundary because any reported mismatch is converted into the explicit load error after prefix normalization and bookkeeping-key removal.

### VAE construction

The VAE is not manually reconstructed from separate configuration and weight files by `load_model`. It uses the fixed bundle directory:

```python
vae_dir = bundle / "Qwen-Image-vae-2d"
vae_model = AutoencoderKLQwenImage2D.from_pretrained(str(vae_dir))
vae_model = vae_model.eval()
vae_model = vae_model.float()
```

No keyword arguments are supplied to `from_pretrained`. Configuration and `diffusion_pytorch_model.safetensors` interpretation are therefore delegated to `AutoencoderKLQwenImage2D.from_pretrained`; this function does not independently validate those two files before the call. Failures from path conversion, construction, `eval()`, or `float()` propagate through the common `load_model` failure path.

### DINO construction

The DINO encoder follows this exact sequence:

```python
dino_model = build_dinov2_vitl14()
dino_model = dino_model.eval()
dino_path = _find_dino(bundle)
dino_state = _load_state(dino_path)
_strict(dino_model, dino_state, dino_path)
dino_model.to(compute_dtype)
```

`build_dinov2_vitl14` receives no arguments. The dtype is the same `compute_dtype` returned earlier by `_dtype(dtype_name, load_device)`; no explicit device is passed in this `to(...)` call. Device residency is deferred to its `ModelPatcher`.

After DiT, VAE, and DINO preparation, `load_model` iterates all three model objects and calls `parameter.requires_grad_(False)` for every parameter. A failure while obtaining or traversing any parameter iterator aborts construction rather than returning a partially frozen owner.

After the DiT, VAE, and DINO model objects and their state have been prepared, `load_model` imports `comfy.model_patcher.ModelPatcher` and constructs three independent patchers:

```python
dit_patcher = ModelPatcher(
    dit_model,
    load_device=load_device,
    offload_device=offload_device,
)
vae_patcher = ModelPatcher(
    vae_model,
    load_device=load_device,
    offload_device=offload_device,
)
dino_patcher = ModelPatcher(
    dino_model,
    load_device=load_device,
    offload_device=offload_device,
)
```

It then returns a newly constructed model owner equivalent to:

```python
TESpeedVOSR2Model(
    dit_patcher,
    vae_patcher,
    dino_patcher,
    args,
    dtype_name,
    compute_dtype,
)
```

The patchers are therefore owned by the returned `TESpeedVOSR2Model`; they are not a shared singleton cache at this boundary. The common construction-failure tail releases Python references, but no `unload_model_and_clones`, `soft_empty_cache`, resource `close`, or explicit rollback call was observed inside `load_model`. This does not prove native/GPU resource leakage—destructors may run during decref—but there is no explicit transactional rollback in this function.

The exact constructor is:

```python
TESpeedVOSR2Model.__init__(
    self,
    dit_patcher,
    vae_patcher,
    dino_patcher,
    args,
    dtype_name,
    compute_dtype,
)
```

All seven slots, including `self`, are required and may be populated positionally or by keyword. The body stores the six supplied fields directly, then initializes:

- `vae_amp = False` and `vae_encode_amp = False`;
- `memory_policy = "auto"`;
- `_active_patcher = None` and `_resident_ready = False`;
- `_dino_norm_cache = {}`;
- `_compile_enabled`, `_compile_requested`, `_compile_first_call`, and `_compile_fallback` to `False`.

It then derives:

```python
dino_size = int(args.get("dinov2_size", 448))
dino_layer = next(iter(args.get("layer_dinov2b_list", [17])))
```

Missing/empty or non-iterable layer data is not silently repaired by the constructor; the corresponding Python exception is preserved. Complete references to the `_resident_ready` name show only assignments of `False`: construction, memory-policy changes, `pin_resident`, and staged cleanup. No assignment of `True` or truth test was observed. Current residency decisions therefore use `_active_patcher`; `_resident_ready` is retained state but is not promoted in the analyzed module.

### Compile policy

```python
model.set_torch_compile(enabled, bundle_dir)
```

normalizes `enabled` to `bool`, records `_compile_requested`, and resets `_compile_first_call` and `_compile_fallback` to false. A false request sets `_compile_enabled = False` and returns `None`.

For a true request it imports `triton`. A matching missing-import failure logs:

```text
[TE-Speed-VOSR2] torch_compile requested but triton is not installed; skipping.
```

and leaves `_compile_enabled = False`. Otherwise it creates bundle-local `_compile` cache directories, sets `TORCHINDUCTOR_CACHE_DIR` and `TRITON_CACHE_DIR` only when absent, and compiles `dit_patcher.model.forward_flexible` through:

```python
torch.compile(
    forward_flexible,
    backend="inductor",
    mode="default",
    dynamic=False,
)
```

The compiled callable is marked with `_te_compiled_flex`; successful installation sets `_compile_enabled = True`. The body contains a warning-and-disable fallback path for compilation failure rather than making compilation mandatory.

### Memory policy and staged cleanup

```python
model.set_memory_policy(policy: str)
```

accepts `"auto"`, `"resident"`, and `"staged"`; any other string is normalized to `"resident"`. When the effective value changes, it resets `_resident_ready = False` and `_active_patcher = None` before assigning `memory_policy`. An unchanged value is returned without resetting readiness.

`pin_resident(self)` does not load a model by itself. It sets `_resident_ready = False` and returns Python `False`, forcing later residency logic to establish the state again.

`_load(self, patcher)` is the common load/validation primitive. In `"staged"` mode, or when `patcher is not self._active_patcher`, it calls:

```python
comfy.model_management.load_models_gpu(
    [patcher],
    force_full_load=True,
)
```

then assigns `_active_patcher = patcher` and returns `(patcher.model, patcher.load_device)`. When the requested patcher is already active in a non-staged policy, `_load` validates that the wrapped model is still on `load_device`, is not marked `model_lowvram`, and has no observed meta parameters. If this validation indicates external offload, it logs:

```text
[TE-Speed-VOSR2] %s was externally offloaded; reloading it
```

sets `_active_patcher = None`, and enters the same full-load path. The validation is therefore an active residency check, not merely an identity-cache hit.

`_load_stage(self, patcher)` delegates directly to `_load` unless `memory_policy == "staged"`. In staged mode it iterates `_patchers`, skips the requested patcher by identity, and calls:

```python
comfy.model_management.unload_model_and_clones(
    other_patcher,
    unload_additional_models=False,
)
```

for every other patcher. Only after that loop completes does it set `_active_patcher = None` and call `_load(self, patcher)`. An unload failure therefore prevents the requested stage load and can leave earlier patchers already unloaded.

`clear_staged(self)` iterates every entry in `self._patchers` and performs the same `unload_model_and_clones(..., unload_additional_models=False)` call. After all unloads succeed it sets `_active_patcher = None`, sets `_resident_ready = False`, calls `comfy.model_management.soft_empty_cache()`, and returns `None`. An iteration or unload failure propagates before the final state reset/cache-emptying sequence; cleanup is therefore not transactional.

`prepare_vae_decode(self)` delegates to `FUN_180012b00` (2,580 bytes). Its recovered transition is:

1. if `self._active_patcher is self.vae_patcher`, return `None` immediately;
2. inspect `self.vae_patcher.load_device.type`;
3. only for `"cuda"`, attempt `torch.cuda.mem_get_info(load_device)` and unpack `(free_bytes, total_bytes)`;
4. failures in that memory-query block matching ordinary `Exception` are suppressed, leaving the free-memory observation unavailable;
5. compare available free memory with `VAE_DECODE_RESERVE`;
6. when free memory is below the reserve, log:

   ```text
   [TE-Speed-VOSR2] releasing DiT/DINO residency for VAE decode (free %.2f GiB, reserve %.2f GiB)
   ```

   using byte-to-GiB conversion by `1073741824`;

7. call `self._unload_transformers()`;
8. return `None`.

The memory-query failure is intentionally non-fatal, but failures in logging or `_unload_transformers()` propagate. This helper releases transformer residency conditionally; it does not itself prove that the VAE patcher has been loaded afterward.

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

### `run_vosr2` calling convention and admission

The public wrapper at `FUN_180033b50` (1,712 bytes) and implementation at `FUN_180034230` establish:

```python
run_vosr2(
    model,
    images,
    scale,
    seed,
    settings,
    batch_override=None,
    temporal_cache=False,
    auto_expand_vae_tile=False,
)
```

The first five parameters are required; the final three may be supplied positionally or by keyword. Generated parser failures retain the Python exception and return native `NULL`.

The implementation validates the ComfyUI image boundary before inference:

- input must have shape `[B, H, W, C]`, otherwise the error begins `TE-Speed-VOSR2 expects IMAGE tensor [B, H, W, C], got shape `;
- the last dimension must contain exactly 3 or 4 channels, otherwise the error is `TE-Speed-VOSR2 supports RGB/RGBA IMAGE input, got <n> channels`;
- four-channel input is replaced by a channel slice before device/model preparation, while three-channel input is retained directly. The alpha channel is therefore discarded rather than restored or composited by the inference workflow;
- the internal VAE path subsequently uses channel-first tensors and the surrounding workflow owns the channel-last/channel-first conversion.

Before choosing an inference route it invokes `_ensure_speed_runtime()` and `_enable_fast_math()`. It resolves the model memory policy, uses the model-level value when the supplied setting is `"auto"`, and resolves a remaining `"auto"` value to `"resident"`. If the model implements `set_memory_policy`, that method is called; otherwise the `memory_policy` attribute is assigned directly.

`batch_override` is converted to `int` and clamped to a minimum of 1 when truthy; a falsey override uses the configured batch value. The route logic compares `tile_strategy` with `"tiled"` and `"full_frame"`. A selected full-frame strategy disables tiled processing. The implementation retains explicit route labels `"streaming"` and `"full_frame"`, and directly resolves `_streaming_tiled` and `_full_frame`.

Both tiled helpers have exact ten-argument calling conventions:

```python
_phased_tiled(
    model,
    source_cpu,
    h,
    w,
    seed,
    settings,
    batch_size,
    device,
    cache_enabled,
    pbar,
)

_streaming_tiled(
    model,
    source_cpu,
    h,
    w,
    seed,
    settings,
    batch_size,
    device,
    cache_enabled,
    pbar,
)
```

Their wrappers require all ten values and permit ordinary positional/keyword population. `_phased_tiled` delegates to `FUN_180023c40` (31,435 bytes); `_streaming_tiled` delegates to `FUN_18002bdc0`. They are parallel implementations with a shared input contract, not aliases.

The complete static name-reference set for `_phased_tiled` contains only its own wrapper/body registration and module-initializer records. No reference from `run_vosr2` was observed. Conversely, `run_vosr2` directly resolves and calls `_streaming_tiled` with ten arguments and requires its result to contain exactly five elements. Therefore the current public workflow uses streaming tiled inference; `_phased_tiled` is retained private code but is not established as an active route.

The five-element `_streaming_tiled` result is an internal调用约定, not the public node result. Structured construction proves:

- element 1 is the effective `settings` object supplied to the helper;
- elements 3 and 4 are retained counters/state values initialized in the streaming body;
- element 0 is the assembled streaming result consumed by `run_vosr2`;
- element 2 is another retained streaming observation.

`run_vosr2` unpacks all five and carries them independently into result assembly. Exact semantic names for elements 2–4 remain Unknown because the native locals are reused across phase and cache branches; they will not be labeled as cache-hit, tile-count, or batch-count values until their producing operations are fully traced.

### Full-frame helper contracts

The active full-frame route has the exact private signature:

```python
_full_frame(
    model,
    resized,
    seed,
    settings,
    feature_cache=None,
    reuse=None,
    keep_cache=False,
    dino_batch=None,
)
```

The first four values are required and all eight may be populated positionally or by keyword. Its associated VAE helpers are:

```python
_encode_resized(model, resized, settings)
_decode_restored(model, restored, mean, std, h, w, settings)
```

All parameters of those two helpers are required. This separates three phases at the private boundary: encode normalized/resized input, run full-frame restoration with optional feature-cache reuse, then decode/crop using the retained `mean`, `std`, `h`, and `w` observations.

`_encode_resized` runs inside `_timed(model, "vae_encode")`. It first calls `_pad_multiple(resized)`, retaining the original spatial dimensions, then calls the model’s VAE encode boundary with the padded tensor plus `settings.vae_tile_size` and `settings.vae_tile_overlap`. The module constants are:

```python
AE_FACTOR = 8
DIT_PATCH = 2
PAD_MULTIPLE = AE_FACTOR * DIT_PATCH  # 16
```

`_pad_multiple(x, multiple=PAD_MULTIPLE)` requires an NCHW tensor, unpacks exactly four shape dimensions, and computes:

```python
pad_h = (-h) % multiple
pad_w = (-w) % multiple
padded = torch.nn.functional.pad(
    x,
    (0, pad_w, 0, pad_h),
    mode="reflect",
)
```

Padding is therefore right/bottom only; batch and channel dimensions are unchanged. It returns the padded tensor together with the original `h` and `w`. `_latent_side(px)` rounds `px` upward to `PAD_MULTIPLE` and then divides by `AE_FACTOR`, equivalent to `ceil(px / 16) * 2` for integers.

The VAE encode call must return exactly three values:

```python
latent, mean, std = model.encode(
    padded,
    settings.vae_tile_size,
    settings.vae_tile_overlap,
)
```

The helper returns the latent data together with `mean`, `std`, and the retained pre-padding dimensions. A CUDA `OutOfMemoryError` invokes `_fallback_vae_tile(settings, exc)` and retries the same encode once under `_timed(model, "vae_encode")` with the replacement settings. Non-CUDA-OOM exceptions propagate.

`_decode_restored` similarly runs under `_timed(model, "vae_decode")`, calls the model decode boundary with `restored`, `mean`, `std`, and the active VAE tile settings, and applies the same one-step CUDA-OOM fallback. The decoded tensor is cropped with four-dimensional indexing equivalent to:

```python
decoded[:, :, :h, :w]
```

It returns a two-element internal tuple containing the cropped tensor and the effective settings object. This proves channel-first spatial processing inside the VAE helpers.

`_finish_batch(decoded, reference, settings, model)` performs the final public IMAGE projection. The recovered order is:

```python
reference_downsample = _color_downsample(settings)
with _timed(model, "color"):
    aligned = decoded.to(
        device=reference.device,
        dtype=torch.float32,
    )
    aligned = (aligned.clamp(-1, 1) + 1) / 2
    aligned = apply_color_alignment(
        aligned,
        reference,
        settings.color_alignment,
        downsample=reference_downsample,
    )

with _timed(model, "d2h"):
    output = aligned.movedim(1, -1).clamp(0, 1).contiguous().cpu()

_flush(model)
return output
```

`_color_downsample(settings)` returns `4` only when `settings.color_alignment == "wavelet"`; all other modes return `1`. That value is passed as the `downsample` keyword to `apply_color_alignment`.

Thus the final boundary converts NCHW to ComfyUI NHWC with `movedim(1, -1)`, bounds values to `[0, 1]`, materializes contiguous storage, transfers to CPU, flushes the model timing/lifecycle helper, and returns the tensor directly. The node wrapper is responsible for placing that tensor in its one-element ComfyUI tuple.

### Temporal-cache decision helpers

The exact private helper signatures are:

```python
_signature(frame)
_cache_hit(current, previous, threshold)
_reuse_flags(
    signatures,
    previous,
    threshold,
    cache_age,
    cache_refresh,
    enabled,
)
```

`_signature` is now fully resolved:

```python
def _signature(frame):
    return torch.nn.functional.interpolate(
        frame[:1].float(),
        size=(32, 32),
        mode="area",
    )
```

It retains only the first entry along dimension 0, converts it to float, and area-downsamples to `32 × 32`. The result is a reduced tensor signature, not a scalar hash.

`_cache_hit` returns false when `previous is None`, tensor shapes differ, or `threshold <= 0`. Otherwise it transfers `previous` to `current.device` and `current.dtype`, computes:

```python
mean(abs(current - previous)) <= float(threshold)
```

and returns that comparison. Conversion/device errors propagate.

`_reuse_flags` first creates a `False` list with `len(signatures)` entries. It leaves that list unchanged unless `enabled` and `signatures` are truthy and `cache_age < cache_refresh`. Under those conditions it computes `_cache_hit(signatures[0], previous, threshold)` and stores the result at index `0`. No loop setting later flag positions was observed in this helper; multi-frame reuse decisions, if any, must be assembled by its callers rather than inferred here.

The implementation records route/result metadata including `quality_profile`, `memory_policy`, `tiled`, attention backend, compile fallback, cache hits, DINO cache hits, tile count, batch count, used batch, and chunk-frame observations. When the effective memory policy is `"staged"`, it resolves and calls `model.clear_staged()` in its post-processing/cleanup region. Exact exception precedence between inference failure and staged cleanup is still Unknown.

### Batch sizing and VAE fallback

`_dit_tile_batch(settings, frame_batch=1)` computes a bounded DiT tile batch. The module constants are:

```python
BALANCED_DIT_TILE_BATCH = 2
SPEED_DIT_TILE_BATCH = 4
```

The recovered formula is:

```python
if settings.quality_profile == "speed":
    divisor = 8
    limit = SPEED_DIT_TILE_BATCH
else:
    divisor = 4
    limit = BALANCED_DIT_TILE_BATCH
return max(1, min(max(1, int(frame_batch)) // divisor, limit))
```

`_fallback_vae_tile(settings, exc)` uses `SAFE_VAE_TILE = 1024`. If `settings.vae_tile_size <= 1024`, it re-raises the supplied exception. Otherwise it logs:

```text
[TE-Speed-VOSR2] VAE tile %s ran out of memory, falling back to %s
```

calls `comfy.model_management.soft_empty_cache()`, and returns the equivalent of:

```python
dataclasses.replace(settings, vae_tile_size=1024)
```

This establishes one bounded VAE downgrade: a tile already at or below 1024 is not retried smaller by this helper.

Other observed diagnostics include:

```text
[TE-Speed-VOSR2] DiT tile batch %s ran out of memory, falling back to %s
[TE-Speed-VOSR2] DiT attention backend for this run: %s
```

The function names and structured body therefore establish full-frame and streaming/tiled routes, phase timing, DINO feature caching, device/CPU movement, bounded OOM fallbacks, VAE preparation, and final batch assembly. Exact tensor formulas, blend weights, cache-signature fields, and DiT OOM retry ordering remain under analysis.

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

1. Recover malformed architecture/state-value error branches and exception identities.
2. Recover exact malformed state-dictionary value filtering and error assembly.
3. Resolve whether `_resident_ready` is a compatibility remnant or used outside this compiled module.
4. Resolve streaming tuple elements 2–4; signature and padding geometry are closed.
5. Trace DiT OOM retry ordering and cleanup/error precedence.

## Evidence identifiers

- `nodes.pyd`: `ev_c94195175c246b11a0b0e0bfef55f5aa7d4bf686526fb218f91e15bb992eec85`
- `settings.pyd`: `ev_efb86b94a29e29830e3725534a4345d3478444bbb19c56466f2af13de6e02a51`
- `model_store.pyd`: `ev_f74f95d36c8116af4a7763803cd348d4feae1075987a7a21666fb61a07ea60dc`
- `inference.pyd`: `ev_53e1cb013a0c53acab344149820c832998fd32511024a1e46a8ec685357c77a8`
