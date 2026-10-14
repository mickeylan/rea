# TE_Qwen Image 2.1 `.pyd` analysis report

> Updated: 2026-10-14
> Target: `TE_Qwen_Image_2_1_Prompt_Enhancer.pyd`
> SHA-256: `17aa8af94035109e882fc4477f21e527d0fef519d38c98c3a730fcda62a42b42`
> Provider: Ghidra 12.1.4 through REA

## Scope and confidence

This report records static observations from the immutable target and conservative deductions from those observations. It does not claim recovery of the original source, exact Python signatures, default values, or runtime behavior. API-provider behavior is intentionally deferred.

- **Observed**: returned directly by Ghidra/REA inventories, references, or function dossiers.
- **Derived**: supported by multiple static observations, but not runtime-verified.
- **Unknown**: not established by the current evidence.

## Module inventory

The public `inspect_cython_extension` workflow reported:

- CPython initializer `PyInit_TE_Qwen_Image_2_1_Prompt_Enhancer` at `0x18002a8a0`.
- 7,780 examined names and 943 examined defined strings.
- 87 qualified-name candidates, 13 Cython markers, and one retained source-path observation.
- Cython runtime identity candidate `_cython_3_1_2limited_fastcallnofinalize`.
- Retained build coordinate `F:\ComfyUI_portable_TE_v260130\ComfyUI\custom_nodes\TE_image\source_py_backup\TE_Qwen_Image_2_1_Prompt_Enhancer.c`.

The target contains the qualified class and method observations:

- `TEQwenImage21PromptEnhancer.INPUT_TYPES`
- `TEQwenImage21PromptEnhancer.enhance_prompt`
- `TEQwenImage21LocalStorage.load` / `.unload`
- `TEQwenImage21OfficialStorage.load` / `.unload`

## `INPUT_TYPES`

### Function boundary

Observed call path:

1. Cython wrapper `FUN_180023cf0`, range `0x180023cf0-0x180023ef1`, 514 bytes.
2. Argument parser `FUN_180031040`, which enforces one exact positional argument for `INPUT_TYPES`.
3. Schema-producing body `FUN_180023f00`, range `0x180023f00-0x180025a51`, 6,994 bytes.

The body constructs Python dictionaries, lists, and tuples using `PyDict_New`, `PyDict_SetItem`, `PyList_New`, `PyList_SetItem`, `PyTuple_New`, and `PyTuple_SetItem`. This establishes that `INPUT_TYPES` dynamically builds a nested ComfyUI-style schema rather than returning one retained literal object.

### Reconstructed schema

The Cython string table is initialized by `FUN_18002f810`. Its 633 static entries map sequentially to the module global slots consumed by `FUN_180023f00`. Resolving that owner representation recovered the following schema without importing the target:

```python
{
    "required": {
        "输入提示词": (
            "STRING",
            {
                "default": "",
                "multiline": True,
                "tooltip": "输入要增强的文生图或图生图需求。",
            },
        ),
        "任务模式": (["文生图", "图生图"], {"default": "文生图"}),
        "输出语言": (
            ["中文", "英文"],
            {
                "default": "中文",
                "tooltip": "控制增强提示词的描述语言。用户明确要求的画面文字保持原文。",
            },
        ),
        "增强方式": (["本地", "本地官方PE", "API"], {"default": "本地"}),
        "api_key": (
            "STRING",
            {
                "default": "",
                "multiline": False,
                "tooltip": "API Key；留空时读取 TE MAN 的 config.ini。",
            },
        ),
        "api_base_url": (
            "STRING",
            {"default": "https://teynex.com", "multiline": False},
        ),
        "model": (
            "STRING",
            {"default": "deepseek-v4.1-flash", "multiline": False},
        ),
        "文生图PE模型": (
            _official_pe_choices(),
            {"tooltip": "本地官方 PE 的文生图模型，增强方式选择本地官方PE且任务模式为文生图时生效。"},
        ),
        "图生图PE模型": (
            _official_pe_choices(),
            {"tooltip": "本地官方 PE 的图生图模型，增强方式选择本地官方PE且任务模式为图生图时生效。"},
        ),
        "主模型": (
            _llm_file_choices(False),
            {"tooltip": "本地 Qwen 视觉模型，文件放在 ComfyUI/models/LLM/。"},
        ),
        "mmproj": (
            _llm_file_choices(True),
            {
                "default": "无",
                "tooltip": "图生图需要选择对应的视觉投影文件。",
            },
        ),
        "最大生成token": (
            "INT",
            {
                "default": 4096,
                "min": 256,
                "max": 32768,
                "step": 256,
                "tooltip": "本地模型最大生成 token。API 模式不发送此限制。",
            },
        ),
        "上下文长度": (
            "INT",
            {
                "default": 8192,
                "min": 1024,
                "max": 327680,
                "step": 256,
                "tooltip": "本地模型的 llama.cpp 上下文长度；数值越大通常占用越多显存。API 模式不使用此设置。",
            },
        ),
        "seed": (
            "INT",
            {
                "default": 0,
                "min": 0,
                "max": 0xFFFFFFFFFFFFFFFF,
                "step": 1,
                "control_after_generate": True,
                "tooltip": "本地模型随机种子。使用生成后控制可固定、递增、递减或随机化；API 模式不使用此设置。",
            },
        ),
        "生成后自动卸载模型": (
            "BOOLEAN",
            {
                "default": False,
                "tooltip": "本地生成完成后自动卸载 Qwen 模型并释放显存。",
            },
        ),
        "启用思考": (
            "BOOLEAN",
            {
                "default": False,
                "tooltip": "仅本地官方 PE 生效。开启后模型先进行思考再输出提示词；关闭后直接生成提示词。",
            },
        ),
    },
    "optional": {
        "图片": ("IMAGE", {"tooltip": "图生图参考图片。"}),
        "图片2": ("IMAGE", {"tooltip": "图生图附加参考图片。"}),
        # 同样结构继续到 图片8
    },
}
```

The optional-name tuple is observed as exactly `图片`, `图片2`, …, `图片8`. Module initialization statically assigns `DEFAULT_API_BASE_URL = "https://teynex.com"`, `DEFAULT_API_MODEL = "deepseek-v4.1-flash"`, `DEFAULT_MAX_OUTPUT_TOKENS = 4096`, and `DEFAULT_CONTEXT_LENGTH = 8192`; the schema above substitutes those observed values.

`_official_pe_choices()` calls `folder_paths.get_filename_list("text_encoders")`, converts the result to a list, sorts it, and returns `['（请把模型放到 models/text_encoders）']` when the list is empty. `_llm_file_choices(is_mmproj)` uses `folder_paths.models_dir/LLM`, integrates an existing `folder_paths.folder_names_and_paths` registration where applicable, recognizes `.gguf`, `.safetensors`, `.bin`, `.pth`, `.pt`, and `folder_paths.supported_pt_extensions`, and filters names based on the `mmproj` marker. It also recognizes multipart GGUF names through `_GGUF_SHARD_PATTERN` and normalizes shard choices. The exact ordering/deduplication details of every fallback branch remain derived rather than runtime-verified.

The user selected static-only analysis, so the target module was not imported. This also corrects the earlier candidate list: `temperature` is retained elsewhere in the module but is not inserted by this `INPUT_TYPES` body.

## `enhance_prompt`

The string `enhance_prompt` at `0x18003b050` has five references. One resolves inside wrapper `FUN_180025e90`, range `0x180025e90-0x180026c60`, 3,537 bytes. The wrapper performs positional/keyword parsing and then dispatches to `FUN_180027200`.

`FUN_180027200`, range `0x180027200-0x18002a09f`, is the observed 11,936-byte method body. Its function dossier contains Python operations for string concatenation, attribute access, list/tuple construction, truth tests, comparisons, vector calls, exception propagation, and generator allocation.

Derived flow:

1. Validate and normalize the caller inputs.
2. Build or select a system prompt and user prompt.
3. Normalize settings such as seed, output language, token budget, and thinking mode.
4. Route to an official, local, or API-backed path.
5. Clean and parse the returned text.
6. Return a one-element Python tuple containing the final enhanced-prompt object.

### Public calling shape

The wrapper's ordered keyword table and arity branches recover the public method shape below. The first 16 arguments after `self` are required; the eight image arguments default to `None`:

```python
def enhance_prompt(
    self,
    输入提示词,
    任务模式,
    输出语言,
    增强方式,
    api_key,
    api_base_url,
    model,
    文生图PE模型,
    图生图PE模型,
    主模型,
    mmproj,
    最大生成token,
    上下文长度,
    seed,
    生成后自动卸载模型,
    启用思考,
    图片=None,
    图片2=None,
    图片3=None,
    图片4=None,
    图片5=None,
    图片6=None,
    图片7=None,
    图片8=None,
):
    ...
```

The Cython wrapper accepts 17–25 positional values including `self`, fills the final eight slots with `None` when omitted, and rejects missing, excess, duplicate, or unexpected arguments. This confirms the order and optionality but not Python source annotations.

On the successful paths, the implementation retains the cleaned/generated prompt object, constructs `PyTuple_New(1)`, stores that object at index 0, and returns the tuple. The compatible high-level return shape is therefore `(enhanced_prompt,)`.

The empty-input branch is also statically resolved: the input is converted to text, stripped, and tested for nonzero Unicode length. An empty result logs `TE Qwen Image 2.1 execute skipped: prompt is empty` and returns the module constant `DAT_180050700`, initialized as the one-element tuple `("",)`. A separate validation branch raises the retained message `图生图模式需要连接图片输入。` when image-to-image mode has no connected image input.

### Normalization helpers

A retained-session analysis of the helper boundaries established:

- `_build_system_prompt` uses wrapper `FUN_180003830` (829 bytes) and body `FUN_180003b70` (1,860 bytes). The wrapper accepts two exact positional values and requires keyword-only `output_language`; the retained positional-name observation is `base_prompt`. The body formats and concatenates Python strings and conditionally tests the supplied objects. Exact language templates remain module-initialized globals.
- `_normalize_seed` is implemented at `FUN_1800042c0` (1,081 bytes) and accepts exactly one observed argument, `seed_value`. It applies `PyNumber_Long`, performs a rich comparison against a retained global threshold, and contains exception matching/restoration. This establishes integer coercion and a threshold/sentinel branch, but not the threshold value or the value chosen by that branch.
- `enable_thinking` at the queried reference belongs to nested `_create_qwen38_text_handler.qwen38_formatter`, `FUN_18000cdc0` (1,113 bytes). Its observed call inputs include `reasoning_effort`, `enable_thinking`, `preserve_thinking`, and `formatter`. The body constructs a keyword dictionary and invokes the retained formatter callable. This is Qwen 3.8 formatting behavior, not proof of the top-level input default.

## Local model route

### Entry and configuration

The `_request_local` wrapper resolves to `FUN_180021e70`, range `0x180021e70-0x1800223b4`, 1,349 bytes. It exposes one positional input plus observed keyword-only configuration names:

- `model`
- `user_prompt`
- `system_prompt`
- `image_base64_list`
- `mmproj`
- `context_length`
- `max_output_tokens`

It dispatches to `FUN_180022710`, a 5,596-byte local-request body. `_local_config` resolves to `FUN_1800216f0` (1,919 bytes), accepts exactly three values corresponding to the retained observations `model`, `mmproj`, and `context_length`, and returns a newly constructed dictionary. Its body coerces the context value with `PyNumber_Long`, applies a retained lower-bound comparison, and inserts both fixed and derived settings. The exact lower bound and dictionary-key mapping remain unresolved global objects.

A retained-session xref pass (one import and one completed Ghidra analysis for all queries) linked the configuration observations more precisely:

- `model` is referenced by the local configuration/body (`FUN_1800216f0`), `_request_local` wrapper (`FUN_180021e70`), `enhance_prompt` wrapper (`FUN_180025e90`), and two additional model-handling functions.
- `mmproj` is referenced by `FUN_1800216f0`, `FUN_180021e70`, and `FUN_180025e90`.
- `context_length` is referenced by `FUN_1800216f0` and `FUN_180021e70`.
- `max_output_tokens` is referenced by `FUN_180021e70` and one additional request function.
- `output_language`, `seed_value`, and `enable_thinking` each resolve to separate helper-function boundaries.

Several duplicate defined strings (`prompt`, `image`, `temperature`) had no direct Ghidra reference at the queried addresses. That is an observed absence of references to those exact data objects, not proof that the settings are unused; Cython may reference a different duplicate object or an initialized global slot.

### Model loading and reuse

`TEQwenImage21LocalStorage.load` has wrapper `FUN_18000ffc0` and 11,228-byte body `FUN_180010230`. Observed strings establish lifecycle branches for:

- `TE Qwen Image 2.1 local model loading model=%s`
- `TE Qwen Image 2.1 local model reusing model=%s`
- `TE Qwen Image 2.1 local model unloading loaded=%s`
- `TE Qwen Image 2.1 local model unloaded`

The load body performs dictionary construction/copy, attribute reads/writes, object calls, comparisons, integer conversion, and exception preservation. It also stores a constructed three-element tuple into the storage object and later reads that state for reuse checks. This supports a derived model-cache lifecycle: reuse aligned loaded state, otherwise unload/reset and create a new local model. Exact tuple member identities, cache keys, and all constructor arguments remain unknown.

### Family selection

`_detect_model_family` is wrapper `FUN_180006ee0`, range `0x180006ee0-0x18000742a`, 1,355 bytes. It validates a string `model_name`, normalizes it through Python method calls, and performs three ordered containment tests before returning one of four retained global values.

Related handler observations are:

- `_create_qwen35_handler` and `Qwen35ChatHandler`
- `_adapt_qwen38_template`
- `_create_qwen38_vision_handler`
- `_create_qwen38_text_handler`
- `Qwen3VLChatHandler`
- `_create_multimodal_handler`

**Derived:** the module distinguishes at least three recognized model-name families plus a fallback and selects text or vision chat formatting accordingly. The exact substrings associated with each returned family are stored in initialized global objects and are not yet resolved.

### GGUF shard validation

`_validate_gguf_shards` has wrapper `FUN_180007960` and body `FUN_180007bb0`, range `0x180007bb0-0x18000929c`, 5,869 bytes. It requires one positional value and keyword-only `file_label`.

Observed shard pattern:

```regex
^(?P<prefix>.+)-(?P<index>\d{5})-of-(?P<total>\d{5})(?P<extension>\.gguf)$
```

The body iterates Python collections, compares values, constructs lists and strings, converts numeric values, and can emit `Expected %s, got %U`. This supports the following derived checks:

- recognize single-file versus numbered multipart GGUF names;
- parse shard index and declared total;
- collect and order expected shard paths;
- reject a missing, mismatched, or inconsistent shard set.

Exact exception classes and every error message remain unknown.

### Multimodal path

Observed values include `llama_cpp.llama_multimodal`, `llama_cpp.llama_chat_format`, `mmproj_path`, `image_base64`, `image_url`, `Qwen3VLChatHandler`, and the Qwen vision template tokens. This establishes an explicit multimodal local path. It does not establish compatibility with every llama.cpp version or model family.

## Deferred and unknown

The following remain intentionally unresolved:

- API request construction, authentication, and provider-specific response handling.
- Runtime filesystem results returned by the two dynamic choice helpers used by `INPUT_TYPES`.
- Exact source annotations and the remaining provider/model-specific error branches of `enhance_prompt`.
- Exact model-family match strings returned by `_detect_model_family`.
- Complete local model constructor arguments and cache identity.
- Runtime behavior for malformed models, unavailable llama.cpp, cancellation, and memory pressure.

## Reproduction commands

```powershell
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"

node scripts/rea.mjs inspect-cython-extension `
  "J:\mickeylan\ComfyUI\custom_nodes\TE_MAN\TE_Qwen_Image_2_1_Prompt_Enhancer.pyd" `
  --provider ghidra --format json

node scripts/rea.mjs function <target> 0x180023f00 --provider ghidra --format json
node scripts/rea.mjs function <target> 0x180027200 --provider ghidra --format json
node scripts/rea.mjs function <target> 0x180006ee0 --provider ghidra --format json
node scripts/rea.mjs function <target> 0x180007bb0 --provider ghidra --format json
node scripts/rea.mjs function <target> 0x180010230 --provider ghidra --format json
node scripts/rea.mjs function <target> 0x180021e70 --provider ghidra --format json
```

All observations above were obtained through ephemeral, read-only Ghidra sessions. The target bytes were not modified.
