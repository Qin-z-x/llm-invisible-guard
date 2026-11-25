"""Prefetch Qwen2.5-0.5B-Instruct into the local HF cache (network used here only)."""
import sys

def main() -> int:
    try:
        from huggingface_hub import snapshot_download
    except Exception as exc:  # pragma: no cover - environment dependent
        print("huggingface_hub unavailable:", type(exc).__name__, exc)
        return 2
    path = snapshot_download(
        "Qwen/Qwen2.5-0.5B-Instruct",
        allow_patterns=["*.json", "*.safetensors", "*.txt", "*.model", "tokenizer*", "vocab*", "merges*"],
    )
    print("MODEL_PATH=" + path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
