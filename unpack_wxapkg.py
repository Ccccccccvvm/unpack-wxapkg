#!/usr/bin/env python3
"""
unpack_wxapkg.py — 解密并解包微信 PC 端 V1MMWX 加密的 .wxapkg 小程序/插件包。

加密方案 (微信 Windows 客户端):
    magic   = b'V1MMWX'                     文件头 6 字节
    key     = PBKDF2-HMAC-SHA1(appid, salt=b'saltiest', iterations=1000, dklen=32)
    iv      = b'the iv: 16 bytes'
    前 1024 字节 (magic 之后)  → AES-256-CBC 解密，取前 1023 字节
    第 1024 字节之后的剩余数据 → 单字节 XOR，key = ord(appid[-2])，长度不足用 0x66('f')
    明文 = AES解密结果[:1023] + XOR结果

明文是标准 (未加密) wxapkg 容器，再按索引表切出每个文件。

用法:
    python3 unpack_wxapkg.py <file.wxapkg> <appid> [-o OUTDIR] [--no-extract]

示例:
    python3 unpack_wxapkg.py __PLUGINCODE__.wxapkg wx3bbab3920eabccb2
"""
import argparse
import hashlib
import os
import struct
import sys

try:
    from Crypto.Cipher import AES  # pip install pycryptodome
except ImportError:
    sys.exit("缺少依赖: pip install pycryptodome")

SALT = b"saltiest"
IV = b"the iv: 16 bytes"
MAGIC = b"V1MMWX"
WXAPKG_FIRST = 0xBE   # 明文 wxapkg 起始标记
WXAPKG_LAST = 0xED    # 索引头结束标记


def decrypt_wxapkg(data: bytes, appid: str) -> bytes:
    """V1MMWX 加密包 -> 明文 wxapkg 字节。"""
    if data[:6] != MAGIC:
        raise ValueError("不是 V1MMWX 加密包 (文件头不匹配)")
    key = hashlib.pbkdf2_hmac("sha1", appid.encode(), SALT, 1000, dklen=32)
    head = AES.new(key, AES.MODE_CBC, IV).decrypt(data[6:6 + 1024])[:1023]
    xor = ord(appid[-2]) if len(appid) >= 2 else 0x66
    tail = bytes(b ^ xor for b in data[6 + 1024:])
    return head + tail


def parse_index(buf: bytes):
    """解析明文 wxapkg 索引，返回 [(name, offset, size), ...]。"""
    if not buf or buf[0] != WXAPKG_FIRST:
        raise ValueError(
            f"解密失败: 首字节 0x{buf[0]:02x} != 0x{WXAPKG_FIRST:02x} (appid 可能不正确)"
        )
    index_len, body_len = struct.unpack(">I", buf[5:9])[0], struct.unpack(">I", buf[9:13])[0]
    if buf[13] != WXAPKG_LAST:
        raise ValueError("索引头结束标记 (0xED) 错误")
    count = struct.unpack(">I", buf[14:18])[0]
    p = 18
    files = []
    for _ in range(count):
        nlen = struct.unpack(">I", buf[p:p + 4])[0]; p += 4
        name = buf[p:p + nlen].decode("utf-8", "replace"); p += nlen
        off, size = struct.unpack(">II", buf[p:p + 8]); p += 8
        files.append((name, off, size))
    return files, index_len, body_len


def extract(buf: bytes, files, outdir: str):
    for name, off, size in files:
        dst = os.path.join(outdir, name.lstrip("/"))
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        with open(dst, "wb") as f:
            f.write(buf[off:off + size])


def main():
    ap = argparse.ArgumentParser(
        description="解密并解包微信 PC 端 V1MMWX 加密的 .wxapkg",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("file", help="加密的 .wxapkg 文件路径")
    ap.add_argument("appid", help="小程序/插件的 appid (如 wx3bbab3920eabccb2)")
    ap.add_argument("-o", "--outdir", help="解包输出目录 (默认 <file>.unpacked)")
    ap.add_argument("--no-extract", action="store_true", help="只解密生成 .dec，不解包文件")
    args = ap.parse_args()

    raw = open(args.file, "rb").read()
    xor = ord(args.appid[-2]) if len(args.appid) >= 2 else 0x66
    print(f"[*] {args.file}  ({len(raw)} bytes)  appid={args.appid}  xor=0x{xor:02x}")

    dec = decrypt_wxapkg(raw, args.appid)
    dec_path = args.file + ".dec"
    open(dec_path, "wb").write(dec)
    print(f"[*] 解密后首字节: 0x{dec[0]:02x}")
    print(f"[+] 明文包已存: {dec_path}")

    files, index_len, body_len = parse_index(dec)
    print(f"[*] wxapkg 校验通过: indexLen={index_len} bodyLen={body_len} 文件数={len(files)}")

    if args.no_extract:
        return
    outdir = args.outdir or args.file + ".unpacked"
    extract(dec, files, outdir)
    print(f"[+] 解出 {len(files)} 个文件到 {outdir}/")
    for name, _off, size in files[:30]:
        print(f"      {size:>9}  {name}")
    if len(files) > 30:
        print(f"      ... 其余 {len(files) - 30} 个")


if __name__ == "__main__":
    main()
