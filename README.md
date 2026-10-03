# fileprotect — 本地文件保护库

为上层系统提供敏感文件的本地加密存储与崩溃安全的密钥轮换。密文存放在本地目录，
密钥与轮换状态存放在 SQLite（`protect.db`）。纯 Python，仅依赖 `cryptography`。

## 能力

| 能力 | API |
| --- | --- |
| 保护导入 | `FileProtector.import_file(file_id, source)` |
| 明文回读 | `FileProtector.read_file(file_id[, dst])` |
| 发起/继续轮换 | `FileProtector.rotate(rotation_id)` |
| 查询状态 | `FileProtector.status()` |

## 快速开始

```python
from fileprotect import FileProtector

with FileProtector("/var/lib/myapp/vault") as fp:
    # 导入：file_id 是调用方提供的稳定标识；导入后回读不再依赖源文件
    fp.import_file("report-2026Q3", "/tmp/report.pdf")

    # 回读：不传 dst 返回 bytes；大文件请传入二进制流以避免整文件入内存
    data = fp.read_file("report-2026Q3")
    with open("/tmp/out.pdf", "wb") as sink:
        fp.read_file("report-2026Q3", sink)

    # 轮换：rotation_id 由调用方提供；同一标识重试=同一轮，幂等续跑
    result = fp.rotate("rotation-2026-10")
    assert result.success

    # 状态：当前轮换标识、目标代次、已完成文件数、是否成功、可用密钥代次
    print(fp.status())
```

## 目录结构（库管理，调用方勿动）

```
vault/
  protect.db   # SQLite：密钥代次、文件注册表、轮换记录
  data/        # 已提交的密文，每个 (文件, 代次) 一份
  tmp/         # 临时密文（绝不出现明文），恢复时自动清理
```

## 安全与崩溃安全设计

- **加密格式**：AES-256-GCM 分块（1 MiB/块）流式加密。每块 nonce 由文件级随机
  base_nonce 与块序号派生，AAD 绑定头部、块序号与结束标记；篡改、重排、截断、
  追加均可检测（抛出 `CorruptCiphertextError`）。处理任意大小文件的额外内存
  远低于 64 MiB。
- **轮换语义**：每次新轮换建立全新密钥代次，逐文件用新密钥真实重加密全部内容
  （不是换包装层）。同一 `rotation_id` 的重试复用已持久化的目标代次，已提交的
  文件进度不会重做；已完成标识再次提交只返回原结果，即使其后完成了更新的轮换。
- **崩溃安全顺序**：新密文先写 `tmp/`、fsync、原子 rename 进 `data/`，再提交
  SQLite（`synchronous=FULL`），最后才删旧密文。因此 DB 记录的代次在磁盘上必然
  有完整密文；中断后文件可能分处新旧两代，但每份密文都完整可解密。
- **恢复**：重新打开库时自动清理 `tmp/`、删除游离密文、补做成功轮换遗留的旧密钥
  清理。恢复过程本身幂等，可被再次中断，最终必定收敛；无需人工修复。
- **完成条件**：全部文件切换到目标代次才报告成功；成功时旧密钥从持久化记录中
  移除，旧密文与临时文件全部清理。

## 运行测试

```bash
python3 -m pytest              # 全部测试（含约 480 MiB 大文件用例）
python3 -m pytest -m "not slow"   # 仅快速用例
```

测试覆盖：部分文件已切换时中断、文件切换与状态更新之间中断、全部切换后旧密钥
未清理时中断、恢复过程再次中断、反复崩溃后最终完成、旧轮换标识在新轮换成功后
再次提交（进度不倒退、不产生多余代次）、密文篡改检测、接近 500 MiB 上限的
大文件回读与内存约束。

## 约束与前提

- 调用串行；轮换未结束时只回读、查询或重试该轮（不导入、不发起新轮换）。
- 导入不会被中断；不考虑断电与硬件损坏（依赖文件系统 fsync 语义）。
- 单文件最大 500 MiB；规模 5000 文件。
