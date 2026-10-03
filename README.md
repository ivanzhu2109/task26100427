# fileprotect — 本地文件保护库

由上层直接调用的 Python 库：敏感文件以 AES-256-GCM 加密存于本地目录，
密钥与轮换恢复状态存于 SQLite（`vault.db`）。支持可中断、可续跑的密钥轮换。

## 能力

- **保护导入** `import_file(file_id, source_path)`：以调用方提供的稳定标识导入；
  内容不可变，不覆盖、不删除；导入成功后回读不再依赖源文件。
- **明文回读** `read_file(file_id, dest_path)`：流式解密到目标路径，
  密文任何损坏都会抛出 `CorruptCiphertextError`。
- **发起/继续轮换** `rotate(rotation_id)`：同一标识的重试属于同一轮，
  接续已提交进度；已完成标识再次提交返回原结果，绝不重新加密或回退代次。
- **查询状态** `status()`：当前轮换标识、目标代次、已完成文件数、
  是否成功、仍可用的密钥代次。

## 用法

```python
from fileprotect import FileProtector

fp = FileProtector("/path/to/vault")   # 目录不存在则创建；重开自动恢复
fp.import_file("doc-001", "/path/to/plain.bin")
fp.read_file("doc-001", "/path/to/out.bin")

result = fp.rotate("2026-Q4-rotation") # 中断后用同一标识再调即可续跑
assert result.done

st = fp.status()
print(st.rotation_id, st.target_generation, st.completed,
      st.done, st.available_generations)
fp.close()
```

## 设计要点

- **加密格式**：AES-256-GCM 分块（4 MiB/块），每块独立 nonce 与认证标签；
  单文件处理峰值内存约 40 MiB（< 64 MiB 约束），与文件大小无关，
  支持 500 MiB 单文件与 5000 文件规模。
- **单文件切换顺序**：写临时密文 → fsync → 原子 rename → 提交数据库 →
  删旧密文。任意点中断后，数据库记录的有效密文始终完整可读。
- **轮换完成**：标记 done 与删除旧密钥在同一 SQLite 事务；
  旧密文与临时文件随后清扫，打开库时也会清理孤儿文件。
- **进度单调**：完成数直接统计文件表，已提交进度不会因重启回退，
  已切换文件在同轮重试时不会再次加密。
- 库管理目录中任何时候都没有明文临时文件；换密钥重加密全程流式，
  明文只存在于内存中。

## 运行测试

```bash
python3 -m pytest tests/ -q          # 全部用例（含约 500 MiB 大文件用例）
python3 -m pytest tests/ -q -k "not large_file"   # 跳过大文件用例
```

测试覆盖：部分文件已切换时中断、切换与状态更新之间中断、全部切换后
旧密钥未清理时中断、恢复过程再次中断、旧轮换标识在后续轮换成功后
再次提交、进度不回退、密文损坏检测、接近单文件上限的回读正确性与
内存约束。
