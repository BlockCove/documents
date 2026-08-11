// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleVault
 * @dev 支付合约 —— 演示 EIP-2612 Permit 的"线下签名 + 第三方提交"支付场景
 *
 * 核心场景：
 *   账户 A 持有大量 MTK，A 线下签名授权本合约划转一定数量的 MTK，
 *   将签名数据交给 B。B 调用 payWithPermit()，代币直接从 A 转到 B。
 *
 *   一笔交易完成：验签 → 授权 → 划转，B 支付 Gas，B 收到代币。
 *
 * 注意：SPENDER_ADDRESS（.env 中配置）就是此合约部署后的地址。
 */

interface IPermitToken {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract SimpleVault {
    address public token;

    event Payment(address indexed from, address indexed to, uint256 amount);

    constructor(address _token) {
        token = _token;
    }

    /**
     * @dev A 签名 → B 提交 → 代币从 A 转到 B
     * @param from     A 的地址（代币持有者、签名者）
     * @param value    支付金额
     * @param deadline 签名截止时间
     * @param v, r, s  A 的线下 EIP-712 签名
     *
     * 调用者（msg.sender = B）支付 Gas，收到代币。
     * 签名中 spender 是本合约地址，value 必须与签名中的 value 一致。
     */
    function payWithPermit(
        address from,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // 1. 验签 + 授权：A 授权本合约划转 value 代币
        IPermitToken(token).permit(from, address(this), value, deadline, v, r, s);

        // 2. 划转：从 A 转到调用者 B
        IERC20(token).transferFrom(from, msg.sender, value);

        emit Payment(from, msg.sender, value);
    }
}
