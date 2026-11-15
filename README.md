# WStop File Rescue

离线的 .wstop 文件恢复工具。针对一种已观察到的 WStop 文件布局，使用至少两组已知原件与加密件，检查复用的密钥流并尝试恢复其他匹配文件。无需安装第三方库，支持 Python 3.10 及以上。

An offline known-plaintext recovery tool for one observed WStop layout. It needs two independent file pairs. The public samples are synthetic and contain no incident data.

## 先运行公开样本

```console
python wstop_rescue.py compare --pair samples/pair-a.txt samples/pair-a.txt.wstop --pair samples/pair-b.txt samples/pair-b.txt.wstop
python wstop_rescue.py recover --pair samples/pair-a.txt samples/pair-a.txt.wstop --pair samples/pair-b.txt samples/pair-b.txt.wstop --input samples/target.txt.wstop --output demo-output
python -m unittest -v
```

输出的 `demo-output/target.txt` 应与 `samples/target.txt` 字节一致。可以用 Windows 的 `Get-FileHash` 或 Linux/macOS 的 `shasum -a 256` 校验。样本和 `generate_samples.py` 均为合成演示，生成器只模拟文件布局。

## 本次恢复公开的密钥流

仓库附带本次实地恢复得到的 [密钥流与校验清单](streams/README.md)。它有 **2,063,922 字节**，与演示样本的合成密钥流分别存放。仅在目标文件的 265 字节标记与清单中的 SHA-256 匹配时，工具才会使用它。仅凭 `.wstop` 后缀无法判断是否匹配。

```console
python wstop_rescue.py recover --stream streams/incident-01.json --input "待恢复目录" --output "恢复结果"
```

把同名的 `.json` 和 `.bin` 放在同一个目录。若标记不匹配，或者前置标记布局所需的密钥流超过已公开长度，工具会跳过该文件。对于末尾标记布局，工具只使用前 65,536 字节处理三个加密区间，因此目标文件可以比公开的密钥流更大。

## 怎么比对

1. 为同一份文件找到加密前的原件和加密后的版本。转码、重新压缩和重新导出的版本通常无法通过比对。
2. 观察到两种布局。第一种由 265 字节的标记开头，后面是加密内容。对跳过标记的内容和原件逐字节异或，即得该原件长度范围内的密钥流。
3. 第二种把同样的标记放在末尾。记录的三个加密区间分别从偏移 `0`、`floor(原始长度 / 2)` 和 `原始长度 - 65536` 开始，每段 65,536 字节。比对原件确认这三段导出的密钥流完全相同，且其余字节一致。
4. 用独立原件复核标记、密钥流的公共前缀和恢复结果。用较长的精确原件可以延长第一种布局的覆盖范围，例如本地旧附件、应用缓存、文件备份或压缩包中的原始成员。
5. 对同一标记的目标文件按相应布局异或。第一种布局只在密钥流覆盖全部文件时输出。对结果做实际格式校验，如检查图片是否能完整解码、文档压缩包的 CRC，以及视频能否读出画面和音轨。

一个字节的演示是 `0x41 XOR 0xE6 = 0xA7`。如果第二个文件在相同偏移也使用 `0xA7`，其密文字节 `0xE5 XOR 0xA7 = 0x42`。这种方法依赖密钥流复用，无法从一个样本推出任意文件的密钥。

## 恢复自己的文件

把示例里的两对输入换成你自己的路径。可以给 `--input` 指定一个文件，或者递归扫描一个目录。把 `--output` 指向输入目录之外的一个新目录。文件会保留相对路径，遇到不匹配的标记、密钥流过短或同名冲突时跳过。工具只写恢复副本，加密输入保留。请在替换任何原目录内容前验证恢复结果。

对于标记不匹配的文件，需要提供该批次的两组原件和加密件。使用其他布局的文件超出本工具范围。这是数据恢复工具，无法判断设备是否仍有恶意软件。即使结构检查通过，也应打开重要文件验证其内容。
