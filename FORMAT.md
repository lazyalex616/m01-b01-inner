# `init.bin` 文件格式

## 设备样本

两份设备样本的包头均为 24 字节。正文使用 AES-128-ECB，密钥和分组均为 128 位；内容为 zlib 压缩的 Lua 文本。两份样本的压缩流均与 zlib 级别 9 的输出逐字节一致。

| 样本 | `init.bin` 字节数 | 压缩流字节数 | Lua 字节数 |
|---|---:|---:|---:|
| 上海 | 244,440 | 244,415 | 1,151,589 |
| 浙江 | 141,160 | 141,134 | 661,590 |

**设备原件 SHA-256**

| 样本 | `init.bin` | 完整 Lua 文本 |
|---|---|---|
| 上海 | `2c5d9b3b7b7e0a0b7022e42d412c48910da5624440383686e293a65878b99022` | `9ed58eeb31e55d25acc32fd09f3d93d63c2dd9ddf740ddc83975604414207079` |
| 浙江 | `58b8df301eebbef83e306cde217097fcbea57561dfe97bac09544ca85c2c695b` | `d8bd1bbb6cc0d2c8cda7730d04b59201cbd8081f1f2c5be1732c4f1e413cc8c3` |

## 仓库文件

| 样本 | 原始二进制 | 完整源码 | 模块及原行号 |
|---|---|---|---|
| 上海 | [init.bin](samples/shanghai/init.bin) | [init.lua](samples/shanghai/init.lua) | [module-index.tsv](samples/shanghai/module-index.tsv) |
| 浙江 | [init.bin](samples/zhejiang/init.bin) | [init.lua](samples/zhejiang/init.lua) | [module-index.tsv](samples/zhejiang/module-index.tsv) |

上述文件保持原始字节，校验值与本页设备原件指纹一致。`init.public.lua` 和 `source-excerpts.md` 为辅助节选，模块原行号对应 `init.lua`。
