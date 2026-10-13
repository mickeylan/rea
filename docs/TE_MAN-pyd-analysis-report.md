# TE_MAN .pyd 文件逆向分析报告

> 分析日期：2026-10-13
> 工具：REA 6.4.0 + Ghidra 12.1.4
> 目标：ComfyUI TE_MAN 自定义节点

---

## 概览

TE_MAN 目录下共有 **28 个 .pyd 文件**，全部为 Cython 编译的 Python 扩展模块。

### 模块分类

| 类别           | 文件                                                                                                                               | 数量 |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---- |
| **视频生成**   | Sora_2_Video_Generator, Grok_Video_Generator, TE_VEO_Video, TE_HappyH_Video, Jimeng_Video_Generator, Save_Video_With_Frame_Capture | 6    |
| **图像生成**   | GPT_Image_2_Generator, Grok_Image_Generator, Gemini_Imagen_Generator, TE_Bernini_R_Generator                                       | 4    |
| **任务调度**   | task_runner                                                                                                                        | 1    |
| **配置管理**   | config_manager                                                                                                                     | 1    |
| **文本处理**   | TE_Prompt_Text, TE_MAN_Text_Tools, TE_Text_Display, TE_H3_Prompt_Enhancer                                                          | 4    |
| **API 客户端** | api_client                                                                                                                         | 1    |
| **图像处理**   | image_codec, TE_Image_Compress, save_image_with_output_core                                                                        | 3    |
| **工具类**     | grid_split_core, config_manager, Save_Image_With_Output                                                                            | 3    |
| **其他**       | TE_Asset_Library, TE_3D_Director, TE_MAN_Chat, TE_Batch_Tools                                                                      | 4    |

---

## 详细分析

### 1. task_runner.pyd — 任务调度器

| 属性            | 值                                  |
| --------------- | ----------------------------------- |
| **模块名**      | `task_runner`                       |
| **Python 路径** | `custom_nodes.TE_image.task_runner` |
| **函数数**      | 260                                 |
| **字符串数**    | 357                                 |
| **入口点**      | `PyInit_task_runner`                |

#### 核心类：BatchGenerationRunner

| 方法              | 功能             |
| ----------------- | ---------------- |
| `__init__`        | 初始化任务运行器 |
| `run`             | 执行任务         |
| `_run_parallel`   | 并行执行多个任务 |
| `_run_sequential` | 顺序执行多个任务 |

#### 类型标注

```
List[TaskType]
TaskType
Callable[[TaskType], ResultType]
future_to_task
```

#### 功能解读

```python
class BatchGenerationRunner:
    """批量生成任务运行器"""

    def __init__(self, tasks: List[TaskType]):
        """初始化任务列表"""
        pass

    def run(self) -> List[ResultType]:
        """执行所有任务"""
        pass

    def _run_parallel(self, tasks: List[TaskType]) -> List[ResultType]:
        """并行执行任务（使用线程池）"""
        pass

    def _run_sequential(self, tasks: List[TaskType]) -> List[ResultType]:
        """顺序执行任务"""
        pass
```

---

### 2. config_manager.pyd — 配置管理器

| 属性            | 值                                     |
| --------------- | -------------------------------------- |
| **模块名**      | `config_manager`                       |
| **Python 路径** | `custom_nodes.TE_image.config_manager` |
| **函数数**      | 358                                    |
| **字符串数**    | 539                                    |
| **入口点**      | `PyInit_config_manager`                |

#### 核心类：ConfigManager

| 方法                           | 功能                    |
| ------------------------------ | ----------------------- |
| `__init__`                     | 初始化配置管理器        |
| `load_api_key`                 | 加载 API 密钥           |
| `sanitize_api_key`             | 清理/格式化 API 密钥    |
| `load_cost_factor`             | 加载费用因子            |
| `clamp_cost_factor`            | 限制费用因子范围        |
| `load_max_workers`             | 加载最大工作线程数      |
| `load_network_workers_cap`     | 加载网络工作线程上限    |
| `get_effective_api_base_url`   | 获取有效的 API 基础 URL |
| `should_bypass_proxy`          | 是否绕过代理            |
| `_parse_bool`                  | 解析布尔值配置          |
| `_decode_api_base_url`         | 解码 API 基础 URL       |
| `_get_default_base_url`        | 获取默认基础 URL        |
| `_is_test_mode_enabled`        | 检查是否启用测试模式    |
| `_load_test_section`           | 加载测试配置节          |
| `_load_test_api_key`           | 加载测试 API 密钥       |
| `_load_test_base_url`          | 加载测试基础 URL        |
| `_ensure_sample_config_exists` | 确保示例配置存在        |

#### 配置文件

- 主配置文件：`config.ini`
- 测试配置文件：`_TEST_CONFIG_FILE_NAME`

#### 使用的 Python 模块

- `ConfigParser` / `configparser` — Python 标准库配置解析

#### 功能解读

```python
class ConfigManager:
    """ComfyUI API 配置管理器"""

    def __init__(self, config_path: str = "config.ini"):
        self._config_path = config_path
        self._test_config_path = ...
        self._config = ConfigParser()

    def load_api_key(self) -> str:
        """从配置文件加载 API 密钥"""
        pass

    def sanitize_api_key(self, key: str) -> str:
        """清理 API 密钥（去除空格等）"""
        pass

    def load_cost_factor(self) -> float:
        """加载费用因子"""
        pass

    def clamp_cost_factor(self, value: float) -> float:
        """限制费用因子在有效范围内"""
        pass

    def get_effective_api_base_url(self) -> str:
        """获取有效的 API 基础 URL（支持测试/生产模式切换）"""
        pass
```

---

### 3. Sora_2_Video_Generator.pyd — Sora 2 视频生成器

| 属性            | 值                                             |
| --------------- | ---------------------------------------------- |
| **模块名**      | `Sora_2_Video_Generator`                       |
| **Python 路径** | `custom_nodes.TE_image.Sora_2_Video_Generator` |
| **入口点**      | `PyInit_Sora_2_Video_Generator`                |

#### 核心类：BananaSora2VideoNode

| 方法             | 功能                     |
| ---------------- | ------------------------ |
| `INPUT_TYPES`    | ComfyUI 节点输入类型定义 |
| `generate_video` | 生成视频                 |

#### 内部方法（私有）

| 方法                         | 功能                  |
| ---------------------------- | --------------------- |
| `_ensure_not_interrupted`    | 确保任务不被中断      |
| `_resolve_videos_url`        | 解析视频 URL          |
| `_resolve_key_and_url`       | 解析 API 密钥和 URL   |
| `_extract_task_id`           | 从响应中提取任务 ID   |
| `_extract_task_status`       | 提取任务状态          |
| `_extract_video_url`         | 提取视频 URL          |
| `_extract_error_message`     | 提取错误消息          |
| `_encode_image_to_data_url`  | 将图片编码为 data URL |
| `_get_output_dir`            | 获取输出目录          |
| `_download_video`            | 下载生成的视频        |
| `_poll_task_until_completed` | 轮询任务直到完成      |

#### ComfyUI 特定字段

```python
# ComfyUI 节点注册
OUTPUT_NODE = True  # 标记为输出节点
NODE_DISPLAY_NAME_MAPPINGS = {...}  # 显示名称映射
NODE_CLASS_MAPPINGS = {...}  # 类映射
```

#### 功能解读

```python
class BananaSora2VideoNode:
    """Sora 2 视频生成节点

    通过轮询 API 状态来生成视频
    """

    @staticmethod
    def INPUT_TYPES():
        """定义节点输入"""
        return {
            "required": {
                "prompt": ("STRING", {...}),
                "api_key": ("STRING", {...}),
                ...
            }
        }

    @staticmethod
    def generate_video(prompt, api_key, ...):
        """生成视频的核心逻辑

        流程：
        1. 编码输入图片为 data URL
        2. 提交任务到 Sora API
        3. 轮询任务状态直到完成
        4. 提取并下载生成的视频
        """
        # 1. 准备数据
        image_data_url = self._encode_image_to_data_url(image)

        # 2. 提交任务
        task_id = self._submit_task(image_data_url, prompt, api_key)

        # 3. 轮询等待
        while True:
            status = self._poll_task_status(task_id)
            if status == "completed":
                video_url = self._extract_video_url(task_id)
                break
            elif status == "failed":
                error = self._extract_error_message(task_id)
                raise VideoGenerationError(error)
            time.sleep(poll_interval)

        # 4. 下载视频
        output_path = self._get_output_dir()
        return self._download_video(video_url, output_path)
```

---

### 4. TE_Prompt_Text.pyd — 文本提示处理

| 属性            | 值                                     |
| --------------- | -------------------------------------- |
| **模块名**      | `TE_Prompt_Text`                       |
| **Python 路径** | `custom_nodes.TE_image.TE_Prompt_Text` |
| **函数数**      | 301                                    |
| **字符串数**    | 411                                    |
| **入口点**      | `PyInit_TE_Prompt_Text`                |

#### 核心类：TEPromptTextNode

| 方法          | 功能                 |
| ------------- | -------------------- |
| `INPUT_TYPES` | 定义节点输入类型     |
| `build_text`  | 构建带引用标签的文本 |

#### API 路由

```
/te_prompt_text/view_reference
```

#### 功能解读

```python
class TEPromptTextNode:
    """文本提示处理节点

    用于在 ComfyUI 中处理带引用标签的文本
    """

    @staticmethod
    def INPUT_TYPES():
        return {
            "required": {
                "text": ("STRING", {"multiline": True})
            },
            "optional": {
                "reference_labels": ("STRING",)
            }
        }

    @staticmethod
    def build_text(text: str, reference_labels: str = None) -> str | tuple:
        """构建带引用标签的文本

        Args:
            text: 输入文本
            reference_labels: 可选的引用标签 (如 "[1,2,3]")

        Returns:
            str: 如果没有 reference_labels
            tuple: (text, {"reference_labels": labels}) 如果提供了
        """
        if not text:
            return ""

        if not isinstance(text, str):
            text = str(text)

        if reference_labels:
            if not isinstance(reference_labels, str):
                reference_labels = str(reference_labels)
            return (text, {"reference_labels": reference_labels})

        return text
```

---

## 共同特征

### 1. 源码路径泄露

所有模块都编译时包含了完整源码路径：

```
F:\ComfyUI_portable_TE_v260130\ComfyUI\custom_nodes\TE_image\source_py_backup\*.py
```

### 2. Python 模块结构

所有模块都遵循 ComfyUI 自定义节点规范：

```python
# 标准结构
class XxxNode:
    @staticmethod
    def INPUT_TYPES():
        """节点输入定义"""
        pass

    @staticmethod
    def FUNC_NAME(...) -> ...:
        """节点核心功能"""
        pass

# ComfyUI 注册
OUTPUT_NODE = True
NODE_CLASS_MAPPINGS = {"XxxNode": XxxNode}
NODE_DISPLAY_NAME_MAPPINGS = {"XxxNode": "Display Name"}
```

### 3. API 配置模式

任务类和生成器都依赖 `ConfigManager` 来获取 API 密钥和配置：

```python
# 典型使用模式
from .config_manager import ConfigManager

class SomeGeneratorNode:
    def __init__(self):
        self.config = ConfigManager()

    def generate(self, ...):
        api_key = self.config.load_api_key()
        base_url = self.config.get_effective_api_base_url()
        ...
```

### 4. 异步任务模式

视频/图像生成器使用轮询模式：

```python
# 典型异步任务流程
task_id = submit_task(...)  # 1. 提交任务
while True:                   # 2. 轮询状态
    status = poll_task(task_id)
    if status == "completed":
        result = get_result(task_id)
        break
    elif status == "failed":
        raise Error(...)
    sleep(poll_interval)
download_result(result)     # 3. 获取结果
```

---

## 架构总结

```
┌─────────────────────────────────────────────────────────────┐
│                     ComfyUI 前端                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                 TE_MAN Custom Nodes                       │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Generator    │  │    Config       │                  │
│  │   Nodes        │  │    Manager      │                  │
│  │  (图像/视频)    │  │                 │                  │
│  └────────┬────────┘  └────────┬────────┘                  │
│           │                     │                           │
│           │    ┌────────────────┘                           │
│           ▼    ▼                                            │
│  ┌─────────────────┐                                       │
│  │  Task Runner    │  ◄── 批量任务调度                      │
│  │  (并行/顺序)    │                                       │
│  └────────┬────────┘                                       │
│           │                                                 │
└───────────┼─────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                  第三方 API                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  │  Sora  │ │  Grok   │ │ Gemini  │ │ Jimeng  │          │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘          │
└─────────────────────────────────────────────────────────────┘
```

---

## 建议

### 1. API 配置集中管理

`ConfigManager` 提供了统一的 API 配置管理，建议其他模块都使用它而不是各自读取配置。

### 2. 任务调度优化

`TaskRunner` 支持并行和顺序执行，可以考虑：

- 添加重试机制
- 添加超时控制
- 支持任务优先级

### 3. 错误处理标准化

建议统一错误处理模式：

```python
try:
    result = await generate(...)
except APIError as e:
    logger.error(f"API Error: {e}")
    raise
except NetworkError as e:
    logger.error(f"Network Error: {e}")
    raise
except TimeoutError as e:
    logger.warning(f"Timeout: {e}")
    raise
```

---

## 参考

- [ComfyUI 自定义节点文档](https://github.com/comfyanonymous/ComfyUI)
- [Cython 官方文档](https://cython.readthedocs.io/)
- [REA 工具](https://rea.tools/)
