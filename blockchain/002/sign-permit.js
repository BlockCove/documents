/**
 * sign-permit.js — EIP-2612 Permit 离线签名脚本
 *
 * 场景：账户 A 持有 MTK，A 线下签名授权 Vault 划转代币，
 *       将签名给 B，B 调用 Vault.payWithPermit()，B 收到代币。
 *
 * 用途：
 *   配合 SimpleTokenWithPermit.sol + SimpleVault.sol 使用，
 *   模拟"账户 A 线下签名"这一步。输出 (from, value, deadline, v, r, s)
 *   复制到 Remix，由账户 B 调用 SimpleVault.payWithPermit()。
 *
 * 使用步骤：
 *   1. 在 Remix 用账户 A 部署 SimpleTokenWithPermit.sol 和 SimpleVault.sol
 *   2. 将合约地址填入 .env：TOKEN_ADDRESS, SPENDER_ADDRESS(=Vault地址)
 *   3. 将 A 的私钥和地址填入 .env：PRIVATE_KEY, OWNER_ADDRESS
 *   4. 运行：node sign-permit.js
 *   5. 复制输出的参数，切换到账户 B，调用 Vault.payWithPermit()
 *
 * 依赖安装：
 *   npm install ethers dotenv
 */

const ethers = require("ethers");
require("dotenv").config();

// ============ 从 .env 读取配置 ============
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const TOKEN_ADDRESS = process.env.TOKEN_ADDRESS;
const OWNER_ADDRESS = process.env.OWNER_ADDRESS;
const SPENDER_ADDRESS = process.env.SPENDER_ADDRESS;
const VALUE = BigInt(process.env.VALUE);
const DEADLINE = parseInt(process.env.DEADLINE);

// ============ 验证配置 ============
function validateConfig() {
  const errors = [];
  if (!PRIVATE_KEY) errors.push("缺少 PRIVATE_KEY");
  if (!TOKEN_ADDRESS) errors.push("缺少 TOKEN_ADDRESS");
  if (!OWNER_ADDRESS) errors.push("缺少 OWNER_ADDRESS");
  if (!SPENDER_ADDRESS) errors.push("缺少 SPENDER_ADDRESS");
  if (!VALUE || VALUE <= 0n) errors.push("缺少或无效的 VALUE");
  if (!DEADLINE || DEADLINE <= Math.floor(Date.now() / 1000)) {
    errors.push("缺少或已过期的 DEADLINE（请设置为未来的时间戳）");
  }
  if (errors.length > 0) {
    console.error("❌ .env 配置错误：");
    errors.forEach((e) => console.error(`   - ${e}`));
    process.exit(1);
  }
}

// ============ 主流程 ============
async function main() {
  validateConfig();

  console.log("========================================");
  console.log("  EIP-2612 Permit 离线签名工具");
  console.log("========================================\n");

  // 1. 创建 Wallet / Signer
  const wallet = new ethers.Wallet(PRIVATE_KEY);
  const signerAddress = await wallet.getAddress();

  console.log(`🔑 签名者地址: ${signerAddress}`);
  console.log(`📄 合约地址:   ${TOKEN_ADDRESS}`);
  console.log(`👤 Owner:      ${OWNER_ADDRESS}`);
  console.log(`🎯 Spender:    ${SPENDER_ADDRESS}`);
  console.log(`💰 Value:      ${ethers.formatUnits(VALUE.toString(), 18)} 代币 (${VALUE} wei)`);
  console.log(`⏰ Deadline:   ${DEADLINE} (${new Date(DEADLINE * 1000).toISOString()})`);

  // 验证签名者是否等于 owner
  if (signerAddress.toLowerCase() !== OWNER_ADDRESS.toLowerCase()) {
    console.warn("\n⚠️  警告：签名者地址与 OWNER_ADDRESS 不一致！");
    console.warn(`   签名者: ${signerAddress}`);
    console.warn(`   Owner:  ${OWNER_ADDRESS}`);
    console.warn("   请确保 PRIVATE_KEY 属于 OWNER_ADDRESS\n");
  }

  // 2. 定义 EIP-712 Domain
  const CHAIN_ID = parseInt(process.env.CHAIN_ID || "31337");
  const TOKEN_NAME = process.env.TOKEN_NAME || "SimpleTokenWithPermit";
  const domain = {
    name: TOKEN_NAME,                 // 必须与合约部署时的 _name 参数完全一致！
    version: "1",
    chainId: CHAIN_ID,
    verifyingContract: TOKEN_ADDRESS,
  };
  console.log(`🔗 Chain ID:   ${CHAIN_ID}`);
  console.log(`🏷️  Token Name: ${TOKEN_NAME}`);

  // 3. 定义 Permit 类型
  const types = {
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  // 4. 构造待签名的 Permit 数据
  //    nonce 需要从链上查询，这里假设为 0（首次签名）
  //    如果不是首次，请修改 nonce 值
  const nonce = 0;

  const message = {
    owner: OWNER_ADDRESS,
    spender: SPENDER_ADDRESS,
    value: VALUE.toString(),    // BigInt -> string for ethers
    nonce: nonce,
    deadline: DEADLINE,
  };

  console.log(`🔢 Nonce:       ${nonce}\n`);

  // 5. 使用 EIP-712 签名
  console.log("📝 正在生成 EIP-712 签名...\n");

  const signature = await wallet.signTypedData(domain, types, message);

  // 6. 分解签名为 v, r, s
  const sig = ethers.Signature.from(signature);

  console.log("========================================");
  console.log("  ✅ 签名生成成功！");
  console.log("========================================\n");

  console.log("📋 完整签名（可验证用）：");
  console.log(`   ${signature}\n`);

  console.log("========================================");
  console.log("  📋 复制以下参数到 Remix 调用 payWithPermit()");
  console.log("========================================\n");

  console.log(`from:     ${OWNER_ADDRESS}   ← A 的地址`);
  console.log(`value:    ${VALUE.toString()}`);
  console.log(`deadline: ${DEADLINE}\n`);

  console.log(`v: ${sig.v}`);
  console.log(`r: ${sig.r}`);
  console.log(`s: ${sig.s}\n`);

  console.log("========================================");
  console.log("  Remix 操作步骤（切换到账户 B！）：");
  console.log("========================================");
  console.log("  1. Remix Account 下拉切换到账户 B");
  console.log("  2. 在 SimpleVault 合约中找到 payWithPermit 函数");
  console.log("  3. 依次填入：from, value, deadline, v, r, s");
  console.log("  4. 点击 transact（账户 B 支付 Gas）");
  console.log("  5. 调用 token.balanceOf(B地址) 验证 B 收到代币\n");
}

main().catch((err) => {
  console.error("❌ 签名失败：", err.message);
  process.exit(1);
});
