/**
 * sign-permit.js — EIP-2612 Permit 离线签名脚本
 *
 * 场景：账户 A 持有 MTK，A 线下签名授权 Vault 划转代币，
 *       将签名给 B，B 调用 Vault.payWithPermit()，B 收到代币。
 *
 * 用途：
 *   配合 SimpleTokenWithPermit.sol + SimpleVault.sol 使用，
 *   模拟"账户 A 线下签名"这一步。输出 (owner, spender, value, deadline, v, r, s)
 *   复制到 Remix，由账户 B 调用 SimpleTokenWithPermit.permit() 或 SimpleVault.payWithPermit()。
 *
 * 使用步骤：
 *   1. 在 Remix 用账户 A 部署 SimpleTokenWithPermit.sol 和 SimpleVault.sol
 *   2. 将合约地址和 A 的账户信息填入 .env
 *   3. 运行：node sign-permit.js <nonce> <spender> <value> <tokenName>
 *      nonce 从 token.nonces(A地址) 查询；spender 为授权对象地址；
 *      value 为授权代币数量（如 100 表示 100 枚）；tokenName 与部署时 _name 一致
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
const DEADLINE = parseInt(process.env.DEADLINE);

// ============ 从命令行参数解析（全部必传） ============
const args = process.argv.slice(2);
if (args.length < 4) {
  console.error("❌ 缺少必传参数");
  console.error("用法: node sign-permit.js <nonce> <spender> <value> <tokenName>");
  console.error("示例: node sign-permit.js 0 0xAbC... 100 MyToken");
  console.error("  nonce     从 token.nonces(A地址) 查询");
  console.error("  spender   授权对象地址");
  console.error("  value     授权数量（代币枚数，脚本自动 ×10^18）");
  console.error("  tokenName 代币名称（必须与部署时 _name 一致）");
  process.exit(1);
}

const NONCE = parseInt(args[0]);
if (isNaN(NONCE) || NONCE < 0) {
  console.error(`❌ nonce 必须是大于等于 0 的整数，收到: ${args[0]}`);
  process.exit(1);
}
const SPENDER_ADDRESS = args[1];
if (!/^0x[0-9a-fA-F]{40}$/.test(SPENDER_ADDRESS)) {
  console.error(`❌ spender 不是有效的以太坊地址，收到: ${SPENDER_ADDRESS}`);
  process.exit(1);
}
const TOKEN_NAME = args[3];

const VALUE_AMOUNT = parseFloat(args[2]);
if (isNaN(VALUE_AMOUNT) || VALUE_AMOUNT <= 0) {
  console.error(`❌ value 必须是大于 0 的数字（代币枚数），收到: ${args[2]}`);
  process.exit(1);
}
const VALUE = BigInt(Math.floor(VALUE_AMOUNT * 10 ** 18));

// ============ 验证配置 ============
function validateConfig() {
  const errors = [];
  if (!PRIVATE_KEY) errors.push("缺少 PRIVATE_KEY");
  if (!TOKEN_ADDRESS) errors.push("缺少 TOKEN_ADDRESS");
  if (!OWNER_ADDRESS) errors.push("缺少 OWNER_ADDRESS");
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
  console.log(`💰 Value:      ${VALUE_AMOUNT} 代币 (${ethers.formatUnits(VALUE.toString(), 18)} 共 ${VALUE} wei)`);
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
  //    nonce 从命令行参数传入（必传）

  const message = {
    owner: OWNER_ADDRESS,
    spender: SPENDER_ADDRESS,
    value: VALUE.toString(),    // BigInt -> string for ethers
    nonce: NONCE,
    deadline: DEADLINE,
  };

  console.log(`🔢 Nonce:       ${NONCE}\n`);

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
  console.log("  📋 复制以下参数到 Remix 调用 permit()");
  console.log("========================================\n");

  console.log(`owner:    ${OWNER_ADDRESS}   ← A 的地址`);
  console.log(`spender:  ${SPENDER_ADDRESS}   ← 授权对象`);
  console.log(`value:    ${VALUE.toString()}`);
  console.log(`deadline: ${DEADLINE}\n`);

  console.log(`v: ${sig.v}`);
  console.log(`r: ${sig.r}`);
  console.log(`s: ${sig.s}\n`);

  console.log("========================================");
  console.log("  Remix 操作步骤（切换到账户 B！）：");
  console.log("========================================");
  console.log("  1. Remix Account 下拉切换到账户 B");
  console.log("  2. 在 SimpleTokenWithPermit 合约中找到 permit 函数");
  console.log("  3. 依次填入：owner, spender, value, deadline, v, r, s");
  console.log("  4. 点击 transact（账户 B 支付 Gas）");
  console.log("  5. 调用 token.allowance(A, spender) 验证授权是否生效\n");
}

main().catch((err) => {
  console.error("❌ 签名失败：", err.message);
  process.exit(1);
});
