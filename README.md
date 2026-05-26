# unpack-wxapkg

解密并解包微信 **PC 端**（Windows 客户端）`V1MMWX` 加密的 `.wxapkg` 小程序 / 插件包，一步还原出里面的源文件。

## 功能

- 解密 `V1MMWX` 加密包 → 标准明文 `.wxapkg`
- 解析 wxapkg 索引表，把每个文件还原到磁盘
- 自动校验（解密后首字节必须是 `0xBE`，appid 错误会立即报错）

## 加密原理

微信 Windows 客户端把下载到的小程序包重新加密成 `V1MMWX` 格式落盘，方案如下：

| 部分 | 处理方式 |
|---|---|
| 文件头 6 字节 | 魔数 `V1MMWX` |
| 密钥派生 | `PBKDF2-HMAC-SHA1(appid, salt="saltiest", iterations=1000, dklen=32)` |
| IV | `"the iv: 16 bytes"`（固定 16 字节） |
| 魔数之后的前 1024 字节 | `AES-256-CBC` 解密，取前 **1023** 字节 |
| 第 1024 字节之后的剩余数据 | 单字节 **XOR**，key = `ord(appid[-2])`，长度不足用 `0x66`（`'f'`） |

最终明文 = `AES解密结果[:1023]` + `XOR结果`，即标准（未加密）wxapkg 容器。

> **密钥就是该小程序 / 插件的 `appid`**（形如 `wx3bbab3920eabccb2`）。没有正确的 appid 无法解密。

## 依赖

```bash
pip install pycryptodome
```

## 用法

```bash
python3 unpack_wxapkg.py <file.wxapkg> <appid> [-o OUTDIR] [--no-extract]
```

| 参数 | 说明 |
|---|---|
| `file` | 加密的 `.wxapkg` 文件路径 |
| `appid` | 小程序 / 插件的 appid |
| `-o, --outdir` | 解包输出目录（默认 `<file>.unpacked`） |
| `--no-extract` | 只解密生成 `.dec`，不解包单个文件 |

### 示例

```bash
python3 unpack_wxapkg.py __PLUGINCODE__.wxapkg wx3bbab3920eabccb2
```

输出：

```
[*] __PLUGINCODE__.wxapkg  (2117422 bytes)  appid=wx3bbab3920eabccb2  xor=0x62
[*] 解密后首字节: 0xbe
[+] 明文包已存: __PLUGINCODE__.wxapkg.dec
[*] wxapkg 校验通过: indexLen=1691 bodyLen=2115710 文件数=31
[+] 解出 31 个文件到 __PLUGINCODE__.wxapkg.unpacked/
           7110  /components/kivicube-collection/images/back.png
            ...
```

产物：

- `<file>.dec` —— 解密后的明文整包（可再喂给其它 wxapkg 工具）
- `<file>.unpacked/` —— 解出的全部源文件

## 如何获取 appid

- 微信 PC 端把包存在 `WeChat Files/Applet/{appid}/` 下，**目录名就是 appid**
- 插件包里的 `appservice.js` 开头一般有 `definePlugin('plugin://wx....')`
- 小程序商店 / 分享链接里的 `appid` 参数

## 解包之后

包里常见两类需要二次处理的文件：

**1. Brotli 压缩的 WASM（`*.wasm.br`）** — 用 Node 内置 zlib 解压：

```bash
node -e "const z=require('zlib'),fs=require('fs');fs.writeFileSync('ar.wasm',z.brotliDecompressSync(fs.readFileSync('ar.wasm.br')))"
```

**2. 压缩打包的 JS（`appservice.js` / `pageframe.js`）** — 美化还原可读性：

```bash
pip install jsbeautifier
python3 -m jsbeautifier appservice.js > appservice.beautified.js
```

## 免责声明

本工具仅用于**安全研究、学习以及对你自己拥有或已获授权的小程序包进行分析**。请遵守相关法律法规与微信平台条款，勿用于侵犯他人知识产权或任何未授权用途。使用者自行承担一切后果。
