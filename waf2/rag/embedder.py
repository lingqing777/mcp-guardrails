"""ONNX Embedding 封装 — 运行时推理

容器运行时只需要 onnxruntime + tokenizers + numpy 三个依赖,
不依赖 PyTorch 或 sentence-transformers。

模型文件结构 (由 scripts/export_onnx.py 生成):
    model/
        model.onnx            — ONNX 格式模型
        tokenizer.json        — HuggingFace tokenizer 配置
        config.json           — 模型元信息 (model_name, max_length, vector_dim 等)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import numpy as np


class OnnxEmbedder:
    """ONNX + tokenizers 纯推理 embedder"""

    def __init__(self, model_dir: Path):
        try:
            import onnxruntime as ort  # type: ignore
            from tokenizers import Tokenizer  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "需要安装 onnxruntime 和 tokenizers: "
                "pip install onnxruntime tokenizers"
            ) from exc

        self.model_dir = Path(model_dir)
        config_path = self.model_dir / "config.json"
        if not config_path.exists():
            raise FileNotFoundError(
                f"缺少 config.json: {config_path}; 请先运行 scripts/export_onnx.py"
            )

        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.model_name: str = config.get("model_name", "unknown")
        self.vector_dim: int = int(config.get("vector_dim", 384))
        self.max_length: int = int(config.get("max_length", 256))

        # 加载 tokenizer
        tokenizer_path = self.model_dir / "tokenizer.json"
        if not tokenizer_path.exists():
            raise FileNotFoundError(f"缺少 tokenizer.json: {tokenizer_path}")
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._tokenizer.enable_truncation(max_length=self.max_length)
        self._tokenizer.enable_padding(length=self.max_length)

        # 加载 ONNX 模型
        onnx_path = self.model_dir / "model.onnx"
        if not onnx_path.exists():
            raise FileNotFoundError(f"缺少 model.onnx: {onnx_path}")

        sess_options = ort.SessionOptions()
        sess_options.intra_op_num_threads = 2  # 容器里不需要太多线程
        self._session = ort.InferenceSession(
            str(onnx_path),
            sess_options=sess_options,
            providers=["CPUExecutionProvider"],
        )

        # 推断输入名 (不同模型可能略有差异)
        self._input_names = [inp.name for inp in self._session.get_inputs()]

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        """返回 shape=(N, vector_dim) 的归一化向量"""
        if not texts:
            return np.zeros((0, self.vector_dim), dtype=np.float32)

        # Tokenize
        encodings = self._tokenizer.encode_batch(list(texts))
        input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
        attention_mask = np.array([e.attention_mask for e in encodings], dtype=np.int64)

        # 构造 ONNX 输入 (只传模型需要的字段)
        feed = {}
        if "input_ids" in self._input_names:
            feed["input_ids"] = input_ids
        if "attention_mask" in self._input_names:
            feed["attention_mask"] = attention_mask
        if "token_type_ids" in self._input_names:
            feed["token_type_ids"] = np.zeros_like(input_ids)

        # 推理
        outputs = self._session.run(None, feed)
        # 大多数 sentence-transformer 导出的 ONNX 第一个输出是 last_hidden_state
        last_hidden = outputs[0]  # shape: (N, seq_len, hidden_dim)

        # Mean pooling (考虑 attention mask)
        mask = attention_mask[:, :, None].astype(np.float32)
        summed = (last_hidden * mask).sum(axis=1)
        counts = mask.sum(axis=1).clip(min=1e-9)
        pooled = summed / counts

        # L2 归一化
        norms = np.linalg.norm(pooled, axis=1, keepdims=True).clip(min=1e-12)
        return (pooled / norms).astype(np.float32)

    def encode_one(self, text: str) -> np.ndarray:
        return self.encode([text])[0]
