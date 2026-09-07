#!/usr/bin/env python3
"""
MPC 多方安全计算 —— Shamir (2,3) 阈值秘密共享演示脚本

场景：
  将一个秘密（例如钱包私钥的数字表示）拆成 3 个分片，
  任意 2 个分片即可恢复原秘密，1 个分片无法恢复。
  分片以 JSON 文件形式存储在本地 shares/ 目录中。
  演示：故意删除其中一个分片文件，用剩余 2 个恢复并验证。

运行：
  python3 mpc_shamir_2of3.py
"""

import json
import os
import secrets
import sys

# ---------------------------------------------------------------------------
# 有限域参数
# ---------------------------------------------------------------------------
# 使用一个 256 位的素数作为有限域模数，足以容纳常见的 32 字节私钥。
# 该值是 secp256k1 曲线的阶 N（私钥的取值范围为 [0, N)），
# 与比特币/以太坊私钥空间一致。注意：这是曲线的阶 N，不是域参数 p。
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

SHARE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shares")


# ---------------------------------------------------------------------------
# 有限域运算辅助
# ---------------------------------------------------------------------------
def mod_inverse(a: int, p: int) -> int:
    """扩展欧几里得算法求 a 在模 p 下的乘法逆元。"""
    if a % p == 0:
        raise ValueError("零没有模逆元")
    return pow(a, -1, p)


# ---------------------------------------------------------------------------
# Shamir 秘密共享：拆分
# ---------------------------------------------------------------------------
def split_secret(secret: int, threshold: int, num_shares: int, prime: int = FIELD_PRIME):
    """
    将秘密 secret 拆分为 num_shares 个分片，任意 threshold 个可恢复。

    原理：构造一个 (threshold-1) 次随机多项式 f(x)，令 f(0) = secret。
          第 i 个分片为点 (i, f(i) mod prime)，i = 1..num_shares。

    返回：[(x1, y1), (x2, y2), ...]
    """
    if secret < 0 or secret >= prime:
        raise ValueError(f"秘密必须在 [0, {prime}) 范围内")
    if threshold > num_shares:
        raise ValueError("阈值不能大于分片总数")
    if threshold < 2:
        raise ValueError("阈值至少为 2（阈值为 1 等于无保护）")

    # 生成多项式的随机系数：系数下标 1..threshold-1，下标 0 是秘密本身
    coefficients = [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]

    shares = []
    for x in range(1, num_shares + 1):
        # 计算 f(x) = sum(coeff[i] * x^i) mod prime
        y = 0
        for power, coeff in enumerate(coefficients):
            y = (y + coeff * pow(x, power, prime)) % prime
        shares.append((x, y))

    return shares


# ---------------------------------------------------------------------------
# Shamir 秘密共享：恢复（拉格朗日插值在 x=0 处求值）
# ---------------------------------------------------------------------------
def recover_secret(shares, prime: int = FIELD_PRIME) -> int:
    """
    用至少 threshold 个分片恢复秘密 f(0)。

    拉格朗日插值公式：
      f(0) = Σ [ y_j * Π (x_i / (x_i - x_j)) ]  (i ≠ j)  mod prime
    其中除法在有限域中通过乘模逆元实现。
    """
    if len(shares) < 2:
        raise ValueError("至少需要 2 个分片才能恢复（2/3 方案）")

    # 检查 x 坐标是否唯一
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("分片的 x 坐标不能重复")

    secret = 0
    for j, (xj, yj) in enumerate(shares):
        # 计算拉格朗日基多项式在 x=0 处的值
        numerator = 1
        denominator = 1
        for i, (xi, _) in enumerate(shares):
            if i == j:
                continue
            numerator = (numerator * xi) % prime
            denominator = (denominator * (xi - xj)) % prime

        # 有限域除法：乘分母的模逆元
        lagrange_coeff = (numerator * mod_inverse(denominator, prime)) % prime
        secret = (secret + yj * lagrange_coeff) % prime

    return secret


# ---------------------------------------------------------------------------
# 分片持久化
# ---------------------------------------------------------------------------
def save_shares(shares, directory: str = SHARE_DIR):
    """将每个分片存为独立的 JSON 文件。"""
    os.makedirs(directory, exist_ok=True)
    paths = []
    for idx, (x, y) in enumerate(shares, start=1):
        path = os.path.join(directory, f"share_{idx}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"index": x, "value": y, "prime": hex(FIELD_PRIME)}, f, indent=2)
        paths.append(path)
    return paths


def load_share(path: str):
    """从 JSON 文件读取单个分片，返回 (x, y)。"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return (data["index"], data["value"])


def load_all_shares(directory: str = SHARE_DIR):
    """读取目录下所有分片文件。"""
    shares = []
    for fname in sorted(os.listdir(directory)):
        if fname.startswith("share_") and fname.endswith(".json"):
            shares.append(load_share(os.path.join(directory, fname)))
    return shares


# ---------------------------------------------------------------------------
# 主流程演示
# ---------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("  MPC 多方安全计算 —— Shamir (2,3) 阈值秘密共享演示")
    print("=" * 70)

    # 1. 设定原始秘密（示例：一个 256 位随机数，模拟钱包私钥）
    original_secret = secrets.randbelow(FIELD_PRIME)
    print(f"\n[1] 原始秘密 (hex): {hex(original_secret)}")
    print(f"    这模拟一个钱包私钥的整数表示。")

    # 2. 拆分为 3 个分片，阈值 2
    threshold = 2
    num_shares = 3
    shares = split_secret(original_secret, threshold, num_shares)
    print(f"\n[2] 拆分为 {num_shares} 个分片，阈值 {threshold}（任意 {threshold} 个可恢复）：")
    for idx, (x, y) in enumerate(shares, start=1):
        print(f"    分片 {idx}: (x={x}, y={hex(y)})")

    # 3. 存储到本地文件
    paths = save_shares(shares)
    print(f"\n[3] 分片已存储到本地文件：")
    for p in paths:
        print(f"    {p}")

    # 4. 验证：用全部 3 个分片恢复
    recovered_all = recover_secret(shares)
    print(f"\n[4] 用全部 3 个分片恢复: {hex(recovered_all)}")
    assert recovered_all == original_secret, "全部分片恢复失败！"
    print("    ✓ 恢复成功，与原始秘密一致")

    # 5. 模拟分片丢失：删除分片 2，只用分片 1 和 3 恢复
    lost_index = 2
    lost_path = os.path.join(SHARE_DIR, f"share_{lost_index}.json")
    print(f"\n[5] 模拟分片丢失：删除 {lost_path}")
    if os.path.exists(lost_path):
        os.remove(lost_path)

    remaining = load_all_shares(SHARE_DIR)
    print(f"    剩余分片数量: {len(remaining)}")
    for idx, (x, y) in enumerate(remaining, start=1):
        print(f"    剩余分片 {idx}: (x={x}, y={hex(y)})")

    # 6. 用剩余 2 个分片恢复
    recovered_partial = recover_secret(remaining)
    print(f"\n[6] 用剩余 {len(remaining)} 个分片恢复: {hex(recovered_partial)}")
    assert recovered_partial == original_secret, "部分分片恢复失败！"
    print("    ✓ 恢复成功，与原始秘密一致")
    print("    结论：即使丢失 1 个分片，剩余 2 个仍可完整恢复秘密。")

    # 7. 反面验证：只用 1 个分片无法恢复（会得到错误结果）
    print(f"\n[7] 反面验证：只用 1 个分片（分片 1）尝试恢复：")
    try:
        recover_secret([shares[0]])
        print("    （理论上不应到达这里，因为阈值为 2）")
    except ValueError as e:
        print(f"    ✗ 无法恢复：{e}")

    # 8. 清理：恢复被删除的分片文件，方便重复运行
    print(f"\n[8] 清理：恢复被删除的分片文件以便下次运行")
    save_shares(shares)

    print("\n" + "=" * 70)
    print("  演示完成。所有分片文件位于 shares/ 目录。")
    print("=" * 70)


if __name__ == "__main__":
    main()
