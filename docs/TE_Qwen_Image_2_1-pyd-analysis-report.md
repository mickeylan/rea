# TE_Qwen Image 2.1 `.pyd` analysis report

> Updated: 2026-10-16
> Target: `TE_Qwen_Image_2_1_Prompt_Enhancer.pyd`
> SHA-256: `17aa8af94035109e882fc4477f21e527d0fef519d38c98c3a730fcda62a42b42`
> Provider: Ghidra 12.1.4 through REA

## Scope and confidence

This report records static observations from the immutable target and conservative deductions from those observations. It does not claim recovery of the original source, source annotations, or runtime behavior. API-provider behavior is described only where the static helper bodies establish it; no network request was sent.

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
- Re-verification on 2026-10-15 produced derived Evidence `ev_2c00ace462678bcea9d66098645aca58ce9905aa81806a9f3e3c3b0a9e9555f6` with `workflow_revision: 1`, complete inventory coverage, and the target digest above.

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

The decoded wrapper dispatch has positional-count cases `0..25`, then merges keyword assignments into the same 25 destination slots. It requires slots `0..16` to be populated, fills slots `17..24` with `None` when absent, and has explicit missing, excess, duplicate, and unexpected-argument error paths. Therefore `17` is the required populated-slot count, not a minimum caller-supplied positional count. All 25 slots participate in positional dispatch, so none of the recovered parameters is keyword-only; however, the public machine-readable convention model continues to retain the final positional bounds as Unknown until parser-state identity and out-of-range dispatch ownership are represented structurally. This confirms the manually decoded order and optionality but not Python source annotations.

### Terminal return paths

`FUN_180027200` has one machine-level return instruction at `0x18002a09f`. All semantic paths converge through cleanup, with `0x18002a073` copying the retained return carrier into `RAX`. Backward tracing separates three outcomes:

| Outcome                            | Return value                                           | Static evidence                                                                                                                                                                                                                                                                                                     |
| ---------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Generated success                  | Newly allocated one-element tuple `(enhanced_prompt,)` | API, local and official-provider success routes converge at `0x180029826`. `0x180029992` supplies tuple size `1`; `0x180029997` calls `PyTuple_New`; `0x1800299a9` increments the cleaned/generated prompt; `0x1800299bc` calls `PyTuple_SetItem` for index `0`; construction success leaves through `0x1800299c4`. |
| Empty normalized prompt            | Retained module tuple `("",)`                          | The skip branch logs `TE Qwen Image 2.1 execute skipped: prompt is empty`, loads `DAT_180050700` at `0x18002814f`, increments it at `0x180028156`, and moves it into the return carrier at `0x18002815c`. Module initialization identifies this constant as `("",)`.                                                |
| Error or raised validation failure | `NULL`, with the Python exception retained/propagated  | Failure paths converge on the error hub near `0x180029ea9`; the generated exception helper records the method context, and `0x180029f8d` clears the return carrier before common cleanup.                                                                                                                           |

The image-to-image/no-image branch belongs to the error outcome: it raises the retained message `图生图模式需要连接图片输入。`; it does not return a warning object.

Other tuple allocations in the body are not public node returns. Static lifetime and use evidence separates them as helper inputs or generator state:

- an eight-element tuple captures image inputs for generator processing;
- a fifteen-element tuple is passed to `_settings_signature`;
- an eight-element tuple carries the image collection to image/provider helpers;
- two-, six-, seven-, and eight-element tuples serve as vectorcall keyword-name or argument metadata for `_build_system_prompt`, `_request_api`, `_request_official_pe`, and `_request_local`;
- each is consumed, transferred, or decremented before the terminal return convergence.

A failure of the public `PyTuple_New(1)` or its item insertion follows error cleanup, so a partially constructed tuple cannot escape. The compatible success return shape is therefore `(enhanced_prompt,)`; empty input returns `("",)`; Python-level failures return no value because the native wrapper returns `NULL` with an exception.

### Normalization helpers

A retained-session analysis of the helper boundaries established:

- `_build_system_prompt` uses wrapper `FUN_180003830` (829 bytes) and body `FUN_180003b70` (1,860 bytes). The wrapper accepts two exact positional values and requires keyword-only `output_language`; the retained positional-name observation is `base_prompt`. The body formats and concatenates Python strings and conditionally tests the supplied objects. Exact language templates remain module-initialized globals.
- `_normalize_seed` is implemented at `FUN_1800042c0` (1,081 bytes) and accepts exactly one argument, `seed_value`, positionally or by keyword. The Cython runtime type check requires a Python integer; an exact `int` is retained, while an integer subtype is normalized through `PyNumber_Long`. At `0x1800045c4-0x1800045d4`, the converted value is compared with initialized integer global `DAT_180051bd0 = 0` using rich-comparison opcode `5` (`Py_GE`). A true comparison returns the normalized integer; a false comparison returns Python `None`. Thus the behavioral contract is `seed if seed >= 0 else None`: zero and positive values are retained, negative values select `None`. Conversion failures are matched against two retained exception-class globals; matching exceptions are cleared and also return `None`, while nonmatching exceptions, comparison failures, and truth-test failures propagate through native `NULL`. The two caught exception-class identities remain Unknown; treating them as `TypeError`/`ValueError` would be a source-level inference rather than a direct observation.
- `enable_thinking` at the queried reference belongs to nested `_create_qwen38_text_handler.qwen38_formatter`, `FUN_18000cdc0` (1,113 bytes). Its observed call inputs include `reasoning_effort`, `enable_thinking`, `preserve_thinking`, and `formatter`. The body constructs a keyword dictionary and invokes the retained formatter callable. This is Qwen 3.8 formatting behavior, not proof of the top-level input default.

## API route

### Function boundaries and call shape

The module method-definition records establish these wrapper entry points:

| Helper                   | Wrapper         | Range / size                           | Implementation body                        |
| ------------------------ | --------------- | -------------------------------------- | ------------------------------------------ |
| `_resolve_api_key`       | `FUN_180019590` | `0x180019590-0x180019e2a`, 2,203 bytes | Logic is retained in this wrapper dossier. |
| `_resolve_api_url`       | `FUN_180019e30` | `0x180019e30-0x18001a3f7`, 1,480 bytes | Logic is retained in this wrapper dossier. |
| `_extract_response_text` | `FUN_18001a400` | `0x18001a400-0x18001a5f8`, 505 bytes   | `FUN_18001b010`, 4,544 bytes.              |
| `_call_chat_completion`  | `FUN_180012e10` | `0x180012e10-0x18001391c`, 2,829 bytes | `FUN_180013920`, 1,498 bytes.              |
| `_build_api_input`       | `FUN_18001d840` | `0x18001d840-0x18001de30`, 1,521 bytes | `FUN_18001de40`, 747-byte generator body.  |
| `_request_api`           | `FUN_18001e130` | `0x18001e130-0x18001e567`, 1,080 bytes | `FUN_18001e570`, 5,704 bytes.              |

`enhance_prompt` resolves the supplied key through `_resolve_api_key(api_key)`, then calls `_request_api` with six keyword arguments in this order: `user_prompt`, `system_prompt`, `api_key`, `api_base_url`, `model`, and `image_base64_list`. The API user text is prefixed with `用户需求：\n`; success enters the shared generated-result cleanup and `(enhanced_prompt,)` return path.

### API key selection

`_resolve_api_key` requires one string argument. It constructs `ConfigManager(PLUGIN_DIR)`, calls `sanitize_api_key` on the supplied node value, and uses the sanitized value when truthy. If it is empty, it calls `load_api_key`, sanitizes that result, and uses it when truthy. If both sources remain empty, it raises the retained message:

```text
请在节点中填写 API Key，或在 config.ini 中配置 API Key
```

This proves the node-value-first, `config.ini` fallback behavior. It does not expose or infer any actual credential value.

### URL normalization

`_resolve_api_url` converts the supplied value to text, applies `strip()`, then `rstrip("/")`. An empty result raises `未配置有效的 API URL`. The helper recognizes already-suffixed URLs ending in:

- `/v1/responses`
- `/responses`
- `/v1/chat/completions`
- `/chat/completions`

It also tests `/v1` and the host marker `api.deepseek.com`, then appends a responses endpoint suffix. Static control flow establishes that the output targets the Responses endpoint family, while preserving the listed already-complete endpoint forms. The exact suffix selected for every `/v1`/DeepSeek combination remains derived because decompiler variable reuse obscures two concatenation operands.

### Request payload and image representation

`_build_api_input(user_prompt, image_base64_list)` constructs the equivalent nested value:

```python
[
    {
        "role": "user",
        "content": [
            {"type": "input_text", "text": user_prompt},
            *(
                {
                    "type": "input_image",
                    "image_url": "data:image/jpeg;base64," + image,
                }
                for image in image_base64_list
            ),
        ],
    }
]
```

`_request_api` strips the selected model and falls back to `DEFAULT_API_MODEL` when empty. It constructs this observed JSON dictionary:

```python
{
    "model": resolved_model,
    "instructions": system_prompt,
    "input": _build_api_input(user_prompt, image_base64_list),
    "temperature": 0.6,
}
```

This `temperature` belongs to the API transport payload. It is not an `INPUT_TYPES` field.

### HTTP transport and errors

The helper imports the initialized `requests` object, resolves `post`, and calls the normalized URL with:

```python
headers = {
    "Authorization": "Bearer " + api_key,
    "Content-Type": "application/json",
}
requests.post(url, headers=headers, json=payload, timeout=300)
```

No request was sent during this analysis. The behavior above comes from static dictionary construction and vectorcall keyword metadata.

The response `status_code` is compared with integer `400`. A status at or above that boundary reads and strips `response.text`, then raises a message of the form:

```text
API 调用失败 HTTP <status>: <text>
```

For a status below 400, the helper calls `response.json()`. If JSON decoding matches either of two retained exception-class globals, it reads and strips `response.text` and raises `API 返回格式异常：<text>`. Other exceptions propagate. The two caught exception identities remain Unknown.

### Exact response precedence

`_extract_response_text` applies this observed priority:

1. return non-empty `payload.get("output_text").strip()` when the value is a string;
2. otherwise try top-level `text` with the same non-empty string rule;
3. iterate `output` (falsey/missing becomes empty), skip non-mappings and entries whose `type == "reasoning"`, and collect readable `content` and `text` fragments;
4. iterate `choices`; for a mapping with mapping-like `message`, read only `message.content`, otherwise accept direct string `choice.text`;
5. inspect exactly two still-unresolved recursive fallback keys and recursively parse mapping values;
6. newline-join retained fragments and strip the result.

A truthy non-iterable `output`/`choices`, or an operation failure while reading, comparing, iterating, joining, or stripping, propagates an exception. If no fragment is recovered, the normal nonraising result is `""`. The internal `read_content` helper and the two recursive key identities remain Unknown.

### Text cleanup and result parsing

The postprocessing helpers resolve to these static boundaries:

| Helper                | Wrapper                      | Implementation                            |
| --------------------- | ---------------------------- | ----------------------------------------- |
| `_clean_think_blocks` | `FUN_180013f00`, 505 bytes   | `FUN_180014100`, 4,187 bytes              |
| `_repair_mojibake`    | `FUN_180015160`, 3,169 bytes | wrapper logic plus three generator bodies |
| `_strip_code_fence`   | `FUN_18001c1d0`, 1,603 bytes | wrapper logic                             |
| `_parse_result`       | `FUN_18001c820`, 505 bytes   | `FUN_18001ca20`, 3,602 bytes              |

`_clean_think_blocks` converts falsey input to `""`, then applies case-insensitive/DOTALL cleanup. Directly observed regular expressions are `<think\\b[^>]*>.*?</think>`, `^.*?</think>\\s*` (at most one leading stray-closing-tag region), fenced `thinking` and `thought` blocks, and `<思考>.*?</思考>`. The body also performs two retained literal `replace` calls whose argument tuples have not yet been decoded, so this is a lower bound on the replacement set.

`_strip_code_fence` converts input to text and strips outer whitespace. It removes a fence only when the entire value matches the case-insensitive expression ` ```(?:json|text|markdown)?\\s*([\\s\\S]*?)\\s*``` `, then returns capture group 1 after `strip()`. Otherwise it returns the already-stripped original text; embedded or partial fences are not removed by this helper.

`_repair_mojibake` converts falsey input to `""`. A retained marker/scoring predicate decides whether repair is worth attempting. When selected, it performs the equivalent codec round trip `text.encode("latin-1").decode("utf-8")`. It computes retained scores for original and candidate text and returns the candidate only when the candidate score compares greater; otherwise it preserves the original. Matching codec failures return the original, while unrelated exceptions propagate. The exact marker sets and score terms live in unresolved initialized tuples/generator constants and remain Unknown.

`_parse_result` applies `_strip_code_fence`, then `_repair_mojibake`. A falsey result raises:

```text
模型返回为空，可能只生成了思考内容但没有最终提示词。请提高最大生成token后重试。
```

It then attempts `json.loads(cleaned_text)`. On `json.JSONDecodeError`, it searches for the first `{` and last `}` and, when they form a non-empty range, retries `json.loads()` on that substring. A second `JSONDecodeError` is treated as a non-JSON result rather than propagated. For a decoded mapping, it reads `rewritten_prompt`, converts it to text, strips it, and uses it only when non-empty; otherwise it falls back to the cleaned string. Non-JSON text is therefore a valid final result.

The proven API postprocessing order is:

```text
response.json()
→ _extract_response_text
→ _clean_think_blocks
→ _parse_result
   → _strip_code_fence
   → _repair_mojibake
→ _text_signature (logging only)
→ return
```

`_call_chat_completion` separately inspects a callable signature and keyword parameter dictionary before invoking a chat-completion callable. Its relationship to the current `requests.post` branch is not proven by a direct call edge in `_request_api`, so it is retained as a related helper rather than claimed as the active transport.

## Local model route

### Entry and configuration

The `_request_local` wrapper resolves to `FUN_180021e70`, range `0x180021e70-0x1800223b4`, 1,349 bytes, and dispatches to `FUN_180022710`, a 5,596-byte local-request body. The caller supplies eight named values in total: `user_prompt`, `system_prompt`, `model`, `mmproj`, `max_output_tokens`, `context_length`, `seed`, and `image_base64_list`; the retained wrapper evidence also identifies the corresponding keyword-parser names. Exact omission/default behavior inside this private helper remains bounded by the caller, which supplies every value.

`_local_config` resolves to `FUN_1800216f0` (1,919 bytes), requires exactly `model`, `mmproj`, and `context_length`, and returns this reconstructed dictionary:

```python
{
    "family": _detect_model_family(model),
    "model": model,
    "mmproj": str(mmproj) if mmproj else "无",
    "think": False,
    "reasoning_effort": "xhigh",
    "n_ctx": max(int(context_length or DEFAULT_CONTEXT_LENGTH), 1024),
    "n_gpu_layers": -1,
}
```

The minimum context is exactly `1024`; falsey context selects `DEFAULT_CONTEXT_LENGTH = 8192`. `n_gpu_layers` is the signed Windows value of initialized `0xffffffff`, hence `-1`. Conversion, comparison, detection, or dictionary failures propagate as Python exceptions.

### Local chat request

The local body loads `TEQwenImage21LocalStorage.load(_local_config(...))` and builds `messages` beginning with:

```python
{"role": "system", "content": system_prompt}
```

With no images, the user message is `{"role": "user", "content": user_prompt}`. With images, `content` becomes a list whose first element is `{"type": "text", "text": user_prompt}` and whose remaining elements come from the eight-image generator. The generator's exact image mapping remains unresolved, so the report does not assume that its schema is identical to the API transport's `input_image` representation.

The request parameter dictionary is exact:

```python
{
    "max_tokens": max(int(max_output_tokens or DEFAULT_MAX_OUTPUT_TOKENS), 256),
    "temperature": 0.7,
    "top_p": 0.9,
    "top_k": 20,
    "repeat_penalty": 1.0,
    "frequency_penalty": 0.0,
    "presence_penalty": 0.0,
    "seed": _normalize_seed(seed),
    "stream": False,
    "stop": ["</s>"],
}
```

Before inference it calls `_reset_llm_state(stored_model.llm)`, then invokes `_call_chat_completion(stored_model.llm, messages=messages, params=params)`. The helper's signature-inspection path filters or adapts parameters according to the selected callable's accepted names/`**kwargs` support.

The result must provide `choices[0].message.content` through mapping/item access. Missing or incompatible structure is translated into `本地模型返回格式异常：<response>`. The content is converted to text, passed through `_clean_think_blocks` and `_parse_result`, and must finish as a string or `None`; helper failures propagate.

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

The load body performs dictionary construction/copy, attribute reads/writes, object calls, comparisons, integer conversion, and exception preservation. The class-level singleton `TEQwenImage21LocalStorage.model` is initialized to `None`. A populated entry is a `TEQwenImage21LocalModel` constructed with the exact named fields `llm`, `settings`, and `chat_handler`; it is not a raw three-element tuple.

Reuse occurs only when `storage.model is not None` and `storage.model.settings == new_settings`. That path logs `TE Qwen Image 2.1 local model reusing model=%s` and returns the existing object. A mismatch logs loading and calls `storage.unload()` before validating or constructing the replacement. Replacement is therefore destructive-first: if later path validation, shard validation, handler creation, or `Llama` construction fails, the old cached model is not preserved.

The settings dictionary passed into `llama_cpp.Llama` is now reconstructed as:

```python
settings = {
    "model_path": resolved_model_path,
    "chat_handler": selected_chat_handler,
    "n_ctx": int(config.get("n_ctx", DEFAULT_CONTEXT_LENGTH)),
    "n_gpu_layers": -1,
    "verbose": False,
}
if _llama_argument_supported("ctx_checkpoints"):
    settings["ctx_checkpoints"] = 0
```

The numeric constants come from the Cython constant initializer: `n_gpu_layers` uses `PyLong_FromLong(0xFFFFFFFF)`, which is signed `-1` on the Windows ABI, while `ctx_checkpoints` uses the initialized integer zero. This equality-tested dictionary is the actual loader cache identity: resolved model path, handler value/object, context size, GPU layers, verbosity, and optional checkpoint setting participate. Prompt text, output-token limit, and seed do not.

Separately, `enhance_prompt` computes a logged `_settings_signature` from fifteen values: task mode, output language, enhancement method, API base URL/model, the two official PE choices, local model, projector, token/context limits, seed, auto-unload, thinking flag, and a derived eight-image signature. This digest is telemetry (`settings_sha256`), not the local model cache key.

`resolved_model_path` is also resolved: it is `os.path.join(folder_paths.models_dir, "LLM", settings["model"])`. The loader requires `os.path.isfile(resolved_model_path)`, raises `找不到模型文件：<path>` when absent, and calls `_validate_gguf_shards(resolved_model_path, file_label="主模型")` before construction. A nonempty `mmproj` value other than `无` is resolved with the same `models_dir/LLM` prefix, checked with `isfile`, and validated with `file_label="mmproj"`; otherwise the effective projector path remains `None`.

### Family selection

`_detect_model_family` is wrapper `FUN_180006ee0`, range `0x180006ee0-0x18000742a`, 1,355 bytes. It validates a string `model_name`, applies `os.path.basename`, lowercases it, and uses the exact ordered routing below:

```python
def _detect_model_family(model_name):
    normalized = os.path.basename(str(model_name) if model_name else "").lower()
    if "qwen3.8" in normalized:
        return "Qwen3.8-VL"
    if "qwen3.6" in normalized:
        return "Qwen3.6-VL"
    if "qwen3.5" in normalized:
        return "Qwen3.5-VL"
    return "Qwen3-VL"
```

Related handler observations are:

- `_create_qwen35_handler` and `Qwen35ChatHandler`
- `_adapt_qwen38_template`
- `_create_qwen38_vision_handler`
- `_create_qwen38_text_handler`
- `Qwen3VLChatHandler`
- `_create_multimodal_handler`

The family strings and return values above are direct static observations. Handler dispatch is now bounded more precisely:

- Qwen 3.5 and Qwen 3.6 with a truthy projector path use `_create_qwen35_handler(projector_path, enable_thinking=think, preserve_thinking=False)`.
- Qwen 3.8 without a projector uses `_create_qwen38_text_handler(llm, enable_thinking=think, preserve_thinking=False, reasoning_effort=reasoning_effort)` and assigns the result to `llm.chat_handler`.
- Qwen 3.8 with a projector uses `_create_qwen38_vision_handler(projector_path, chat_template=template, enable_thinking=think, preserve_thinking=False, reasoning_effort=reasoning_effort)` and assigns the result to `llm.chat_handler`.
- The fallback Qwen 3 VL projector route requires `Qwen3VLChatHandler`; missing support raises `当前 llama-cpp-python 不支持 Qwen3VLChatHandler，请更新 llama-cpp-python。` and delegates construction through `_create_multimodal_handler`.

Branches without a projector retain `None` unless a post-construction Qwen 3.8 text handler is installed. Some fallback multimodal constructor details remain unresolved.

### Automatic unload and exception precedence

Auto-unload is route-specific. The API route does not touch local or official storage. After successful local generation, a truthy `生成后自动卸载模型` calls `TEQwenImage21LocalStorage.unload()`; the official-PE route calls its own storage class. Unload happens before completion logging and before constructing the public one-element return tuple.

The same cleanup is attempted on local/official request failures while preserving the active exception. If unload succeeds, the original request exception is restored. If unload itself raises, that cleanup failure supersedes the saved request exception. Likewise, a successful generation followed by unload failure does not return success. Successful unload return values are ignored. The standalone unload body's internal close/GC ordering remains Unknown.

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

- Exact exception-class identities caught during API-key import, JSON decoding, codec repair, and related provider fallbacks.
- The exact endpoint suffix selected for every `/v1` and `api.deepseek.com` URL combination where decompiler variable reuse obscures a concatenation operand.
- The two recursive response-fallback keys, `read_content`'s complete accepted shape set, two literal think-block replacements, and the mojibake marker/score tables retained in initialized globals.
- Runtime filesystem results returned by the two dynamic choice helpers used by `INPUT_TYPES`.
- Exact source annotations and the remaining provider/model-specific error branches of `enhance_prompt`.
- Remaining fallback multimodal handler constructor details and template adaptation edge cases.
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
