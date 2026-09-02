#!/usr/bin/env python3
"""
RSA 非对称加密 Demo
====================
场景一：私钥签名 → 公钥验签（数字签名，证明身份+防篡改）
场景二：签名 + 加密结合（混合加密 Hybrid Encryption，既保密又认证）

运行：
  pip install cryptography
  python rsa_demo.py
"""

import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# ============================================================
# 工具函数：密钥生成与保存
# ============================================================
def generate_keypair():
    """生成 2048 位 RSA 密钥对"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def save_keys(private_key, public_key, priv_path, pub_path):
    """保存私钥和公钥为 PEM 文件"""
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    return priv_path, pub_path


def load_public_key(pub_path):
    """从 PEM 文件加载公钥"""
    with open(pub_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def key_fingerprint(public_key) -> str:
    """计算公钥指纹（SHA-256 前16位），用于验证公钥身份"""
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_bytes)
    fp = digest.finalize()
    return fp.hex()[:16]


# ============================================================
# 场景一：数字签名（私钥签名 → 公钥验签）
# ============================================================
def sign_message(private_key, message: bytes) -> bytes:
    """用私钥对消息签名（PSS + SHA-256）"""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """用公钥验证签名，返回 True/False"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ============================================================
# 场景二辅助：RSA 加密/解密（用于加密 AES 密钥）
# ============================================================
def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """用 RSA 公钥加密（OAEP + SHA-256），仅用于加密短数据（如 AES 密钥）"""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """用 RSA 私钥解密"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ============================================================
# 场景二辅助：AES-GCM 对称加密（用于加密实际数据）
# ============================================================
def aes_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    AES-256-GCM 加密，返回 nonce(12字节) + ciphertext + tag(16字节)
    GCM 模式同时提供加密和完整性校验。
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96位随机数，GCM推荐
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext  # nonce 和密文打包在一起


def aes_decrypt(key: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
    """AES-256-GCM 解密，data = nonce(12) + ciphertext + tag"""
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ============================================================
# 日志工具：模拟两端对话
# ============================================================
def log(sender: str, msg: str, color: str = ""):
    """格式化输出日志，模拟对话"""
    prefix = f"[{sender}]"
    if sender == "Alice":
        prefix = f"\033[94m[{sender}]\033[0m"   # 蓝色
    elif sender == "Bob":
        prefix = f"\033[92m[{sender}]\033[0m"     # 绿色
    elif sender == "网络":
        prefix = f"\033[93m[{sender}]\033[0m"      # 黄色
    elif sender == "系统":
        prefix = f"\033[90m[{sender}]\033[0m"      # 灰色
    print(f"  {prefix} {msg}")


def separator(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ============================================================
# 场景一演示：数字签名
# ============================================================
def demo_signature():
    separator("场景一：数字签名（私钥签名 → 公钥验签）")

    log("系统", "Alice 本地生成 RSA 密钥对（2048位）")
    alice_priv, alice_pub = generate_keypair()
    save_keys(alice_priv, alice_pub, "alice_private.pem", "alice_public.pem")
    log("Alice", f"私钥已保存到 alice_private.pem（仅我持有）")
    log("Alice", f"公钥已保存到 alice_public.pem（指纹: {key_fingerprint(alice_pub)}），可以公开分发")

    log("Alice", "将公钥通过可信渠道发给 Bob（邮件/GitHub/证书等）")
    log("Bob", f"收到 Alice 的公钥，验证指纹: {key_fingerprint(alice_pub)} ✓")

    # Alice 签名
    message = b"Hello Bob, this is Alice. Transfer 100 USDC to 0x1234...abcd"
    log("Alice", f"准备发送消息: \"{message.decode()}\"")
    log("Alice", "用我的私钥对消息签名（PSS + SHA-256）...")
    signature = sign_message(alice_priv, message)
    log("Alice", f"签名完成（{len(signature)}字节）: {base64.b64encode(signature).decode()[:60]}...")

    # 网络传输
    log("网络", "传输中... 明文 + 签名（明文不保密，任何人都能看到）")

    # Bob 验签
    log("Bob", "收到明文 + 签名")
    log("Bob", "对收到的明文重新计算 SHA-256 哈希...")
    bob_pub = load_public_key("alice_public.pem")
    log("Bob", "用 Alice 的公钥执行验签算法（PSS 概率性验证，不是'解开'签名）...")
    is_valid = verify_signature(bob_pub, message, signature)
    if is_valid:
        log("Bob", "\033[92m✅ 验签通过！消息确实来自 Alice 且未被篡改\033[0m")
    else:
        log("Bob", "\033[91m❌ 验签失败！消息被篡改或不是 Alice 发出的\033[0m")

    # 篡改检测
    log("系统", "--- 模拟中间人篡改 ---")
    tampered = b"Hello Bob, this is Alice. Transfer 9999 USDC to 0xEVIL...hacker"
    log("网络", f"中间人篡改消息为: \"{tampered.decode()}\"")
    log("Bob", "用原签名验证篡改后的消息...")
    is_valid2 = verify_signature(bob_pub, tampered, signature)
    log("Bob", f"\033[91m❌ 验签失败（正确检测到篡改）\033[0m" if not is_valid2 else "⚠️ 验签通过（异常！）")

    log("系统", "场景一结束：数字签名只能证明身份和完整性，不能保密（明文是公开传输的）")


# ============================================================
# 场景二演示：签名 + 加密结合（混合加密 Hybrid Encryption）
# ============================================================
def demo_sign_and_encrypt():
    separator("场景二：签名 + 加密结合（混合加密，既保密又认证）")

    # ---- 初始化：双方各生成密钥对，交换公钥 ----
    log("系统", "初始化：Alice 和 Bob 各生成自己的 RSA 密钥对")
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    save_keys(alice_priv, alice_pub, "alice_private.pem", "alice_public.pem")
    save_keys(bob_priv, bob_pub, "bob_private.pem", "bob_public.pem")

    log("Alice", f"我的公钥指纹: {key_fingerprint(alice_pub)}（发给 Bob）")
    log("Bob", f"我的公钥指纹: {key_fingerprint(bob_pub)}（发给 Alice）")
    log("系统", "双方通过可信渠道交换公钥（验证指纹防止中间人掉包）")

    # ---- Alice 侧：先签名，再加密 ----
    plaintext = b"Hello Bob, this is Alice. Transfer 100 USDC to 0x1234...abcd. Confidential."
    log("Alice", f"准备发送机密消息: \"{plaintext.decode()}\"")

    # 步骤①：Alice 用自己的私钥签名
    log("Alice", "步骤① 用我的私钥对明文签名（证明是我发的、没被改）...")
    signature = sign_message(alice_priv, plaintext)
    log("Alice", f"  签名完成（{len(signature)}字节）")

    # 打包：明文 + 签名
    # 格式：签名长度(4字节大端) + 签名 + 明文
    sig_len = len(signature).to_bytes(4, "big")
    data_to_encrypt = sig_len + signature + plaintext
    log("Alice", f"  打包「明文+签名」共 {len(data_to_encrypt)} 字节（签名{len(signature)}字节 + 明文{len(plaintext)}字节）")

    # 步骤②：生成随机 AES-256 密钥，加密「明文+签名」
    log("Alice", "步骤② 生成随机 AES-256 密钥（32字节），用 AES-GCM 加密「明文+签名」...")
    aes_key = os.urandom(32)  # AES-256
    encrypted_data = aes_encrypt(aes_key, data_to_encrypt)
    log("Alice", f"  AES 加密完成（{len(encrypted_data)}字节，含 nonce+密文+tag）")

    # 步骤③：用 Bob 的 RSA 公钥加密 AES 密钥
    log("Alice", "步骤③ 用 Bob 的 RSA 公钥加密 AES 密钥（只有 Bob 的私钥能解开）...")
    encrypted_aes_key = rsa_encrypt(bob_pub, aes_key)
    log("Alice", f"  RSA 加密 AES 密钥完成（{len(encrypted_aes_key)}字节）")

    # 最终传输包：加密的AES密钥 + AES加密后的数据
    transmit_package = encrypted_aes_key + encrypted_data
    log("Alice", f"最终传输包大小: {len(transmit_package)} 字节（RSA加密的AES密钥 {len(encrypted_aes_key)}B + AES密文 {len(encrypted_data)}B）")
    log("Alice", "发送给 Bob！")

    # ---- 网络传输 ----
    log("网络", f"传输中... 包大小 {len(transmit_package)} 字节")
    log("网络", "中间人即使截获也无法解密（没有 Bob 的私钥就拿不到 AES 密钥）")

    # ---- Bob 侧：先解密，再验签 ----
    log("Bob", "收到传输包！")

    # 步骤④：Bob 用自己的私钥解密 AES 密钥
    log("Bob", "步骤④ 用我的私钥解密，得到 AES 密钥...")
    enc_aes_key_len = 256  # RSA 2048位加密结果固定256字节
    received_enc_aes_key = transmit_package[:enc_aes_key_len]
    received_enc_data = transmit_package[enc_aes_key_len:]
    decrypted_aes_key = rsa_decrypt(bob_priv, received_enc_aes_key)
    log("Bob", f"  AES 密钥解密成功（{len(decrypted_aes_key)}字节）")

    # 步骤⑤：用 AES 密钥解密数据，得到「明文+签名」
    log("Bob", "步骤⑤ 用 AES 密钥解密数据（AES-GCM 同时校验完整性）...")
    try:
        decrypted_data = aes_decrypt(decrypted_aes_key, received_enc_data)
        log("Bob", "  AES 解密成功，GCM 完整性校验通过 ✓")
    except Exception as e:
        log("Bob", f"\033[91m  AES 解密失败！数据被篡改: {e}\033[0m")
        return

    # 解包：签名长度 + 签名 + 明文
    sig_len = int.from_bytes(decrypted_data[:4], "big")
    received_signature = decrypted_data[4 : 4 + sig_len]
    received_plaintext = decrypted_data[4 + sig_len :]
    log("Bob", f"  解包得到：签名 {len(received_signature)}字节 + 明文 {len(received_plaintext)}字节")

    # 步骤⑥：用 Alice 的公钥验签
    log("Bob", "步骤⑥ 用 Alice 的公钥验证签名（确认消息来自 Alice 且未被篡改）...")
    is_valid = verify_signature(alice_pub, received_plaintext, received_signature)
    if is_valid:
        log("Bob", f"\033[92m✅ 验签通过！明文: \"{received_plaintext.decode()}\"\033[0m")
        log("Bob", "\033[92m   确认：只有我能看懂（保密）+ 确实来自 Alice（认证）\033[0m")
    else:
        log("Bob", "\033[91m❌ 验签失败！消息可能被篡改或不是 Alice 发出的\033[0m")

    # ---- 模拟攻击：中间人篡改密文 ----
    log("系统", "--- 模拟中间人篡改密文 ---")
    tampered_package = bytearray(transmit_package)
    tampered_package[-1] ^= 0xFF  # 翻转最后一个字节
    log("网络", "中间人篡改了密文的最后一个字节")
    log("Bob", "尝试解密被篡改的密文...")
    try:
        aes_decrypt(decrypted_aes_key, bytes(tampered_package[enc_aes_key_len:]))
        log("Bob", "⚠️ 解密成功（异常！GCM 应该检测到篡改）")
    except Exception as e:
        log("Bob", f"\033[91m❌ AES-GCM 检测到篡改，解密失败: {type(e).__name__}\033[0m")

    log("系统", "场景二结束：混合加密 = RSA(保密AES密钥) + AES(加密数据) + RSA签名(认证身份)")


# ============================================================
# 主函数
# ============================================================
def main():
    print("\n" + "█" * 60)
    print("  RSA 非对称加密 Demo：签名 + 加密 完整演示")
    print("█" * 60)

    # 场景一：数字签名
    demo_signature()

    # 场景二：签名+加密结合
    demo_sign_and_encrypt()

    # 总结
    separator("总结")
    print("""
  场景一（数字签名）：
    私钥签名 → 公钥验签
    目的：证明身份 + 防篡改 + 防抵赖
    局限：明文公开传输，不保密

  场景二（签名+加密结合，工程标准）：
    Alice：① 私钥签名 → ② AES加密「明文+签名」→ ③ Bob公钥加密AES密钥
    Bob：  ④ 私钥解密AES密钥 → ⑤ AES解密 → ⑥ Alice公钥验签
    目的：既保密（只有Bob能看懂）又认证（确认来自Alice）

  为什么用混合加密？
    RSA 2048位+OAEP最多加密约190字节，签名就有256字节
    → 用 AES 加密大量数据（快、无长度限制）
    → 用 RSA 加密 AES 密钥（安全交换密钥）
    """)


if __name__ == "__main__":
    main()
