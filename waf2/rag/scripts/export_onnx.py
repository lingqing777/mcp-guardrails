"""导出 all-MiniLM-L6-v2 为 ONNX 格式

开发环境依赖:
    pip install sentence-transformers optimum[onnxruntime] onnx

运行:
    python -m waf2.rag.scripts.export_onnx

输出:
    waf2/rag/data/model/
        model.onnx
        tokenizer.json
        config.json
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

MODEL_DIR = PROJECT_ROOT / "waf2" / "rag" / "data" / "model"
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MAX_LENGTH = 256
VECTOR_DIM = 384


def main() -> None:
    try:
        from optimum.onnxruntime import ORTModelForFeatureExtraction  # type: ignore
        from transformers import AutoTokenizer  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "❌ 缺少开发依赖: pip install sentence-transformers optimum[onnxruntime] onnx transformers"
        ) from exc

    print(f"[export_onnx] 🧊 导出模型 {MODEL_NAME} → ONNX")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 下载 HuggingFace 模型并导出为 ONNX
    # export=True 会自动把 PyTorch 模型转 ONNX
    print(f"[export_onnx]    下载并转换...")
    ort_model = ORTModelForFeatureExtraction.from_pretrained(MODEL_NAME, export=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    # 2. 保存到目标目录
    tmp_dir = MODEL_DIR / "_tmp"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    ort_model.save_pretrained(tmp_dir)
    tokenizer.save_pretrained(tmp_dir)

    # optimum 生成的 ONNX 文件名可能是 model.onnx 或 model_quantized.onnx
    onnx_src = tmp_dir / "model.onnx"
    if not onnx_src.exists():
        # 找任意一个 .onnx
        onnx_candidates = list(tmp_dir.glob("*.onnx"))
        if not onnx_candidates:
            raise SystemExit(f"❌ 未找到导出的 ONNX 文件: {tmp_dir}")
        onnx_src = onnx_candidates[0]

    tokenizer_src = tmp_dir / "tokenizer.json"
    if not tokenizer_src.exists():
        raise SystemExit(f"❌ 未找到 tokenizer.json: {tmp_dir}")

    # 3. 拷贝到 MODEL_DIR (只保留必要文件)
    shutil.copy2(onnx_src, MODEL_DIR / "model.onnx")
    shutil.copy2(tokenizer_src, MODEL_DIR / "tokenizer.json")

    config = {
        "model_name": MODEL_NAME,
        "vector_dim": VECTOR_DIM,
        "max_length": MAX_LENGTH,
    }
    (MODEL_DIR / "config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # 4. 清理临时目录
    shutil.rmtree(tmp_dir)

    onnx_size_mb = (MODEL_DIR / "model.onnx").stat().st_size / 1024 / 1024
    print(f"[export_onnx] ✅ 导出完成")
    print(f"[export_onnx]    model.onnx     {onnx_size_mb:.1f} MB")
    print(f"[export_onnx]    tokenizer.json")
    print(f"[export_onnx]    config.json    {config}")
    print(f"[export_onnx] 📁 输出: {MODEL_DIR}")


if __name__ == "__main__":
    main()
