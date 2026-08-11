// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleTokenWithPermit
 * @dev 一个简单的 ERC20 代币，支持 EIP-2612 Permit（链下签名授权）
 *
 * 核心功能：
 *   1. 标准 ERC20：transfer / approve / transferFrom
 *   2. EIP-2612 Permit：链下签名 → 任意账户调用 permit() 上链设置 allowance
 *   3. EIP-712 结构化签名：使用 typed data hash 防钓鱼、可读性强
 *
 * 测试方式：
 *   1. 在 Remix 部署此合约
 *   2. 使用 sign-permit.js 脚本生成链下签名
 *   3. 在 Remix 调用 permit() 传入签名参数，验证 allowance 是否设置成功
 */
contract SimpleTokenWithPermit {
    // ============ ERC20 状态变量 ============
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ============ EIP-2612 Permit 状态变量 ============

    // 每个 owner 的 nonce，防止签名重放
    mapping(address => uint256) public nonces;

    // ============ EIP-712 类型哈希常量 ============

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 private constant PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    // ============ EIP-712 域分隔符（缓存） ============
    bytes32 private _domainSeparator;
    // 构造时的 chainId，用于检测跨链并重新计算 domainSeparator
    uint256 private immutable _cachedChainId;

    // ============ 事件 ============
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ============ 错误 ============
    error PermitExpired();                    // 签名已过期
    error InvalidSigner();                     // 签名验证失败（恢复出的地址与 owner 不一致）
    error PermitDeadlineExpired(uint256 deadline);
    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
    error ERC20InsufficientAllowance(address spender, uint256 allowed, uint256 needed);

    /**
     * @dev 构造函数：初始化代币名称、符号，铸造初始供应量给部署者，计算域分隔符
     */
    constructor(string memory _name, string memory _symbol, uint256 _initialSupply) {
        name = _name;
        symbol = _symbol;
        totalSupply = _initialSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);

        _cachedChainId = block.chainid;
        _domainSeparator = _computeDomainSeparator();
    }

    // ============ ERC20 核心函数 ============

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert ERC20InsufficientAllowance(msg.sender, allowed, value);
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    // ============ EIP-2612 Permit 核心函数 ============

    /**
     * @dev 链下签名 → 链上设置 allowance
     * @param owner    代币持有者地址
     * @param spender  被授权地址
     * @param value    授权额度
     * @param deadline 签名过期时间戳（秒）
     * @param v        签名 v 值 (27 或 28)
     * @param r        签名 r 值
     * @param s        签名 s 值
     *
     * 调用者可以是任意地址（不一定是 owner），Gas 由调用者支付
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // 1. 检查签名是否过期
        if (block.timestamp > deadline) revert PermitExpired();

        // 2. 获取当前 nonce 并递增（防重放）
        uint256 nonce = nonces[owner];
        nonces[owner] = nonce + 1;

        // 3. 重建 EIP-712 结构哈希
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonce,
                deadline
            )
        );

        // 4. 重建 EIP-712 完整签名哈希
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );

        // 5. 从签名恢复地址并验证
        address recovered = ecrecover(digest, v, r, s);
        if (recovered != owner || recovered == address(0)) {
            revert InvalidSigner();
        }

        // 6. 设置授权额度
        _approve(owner, spender, value);
    }

    /**
     * @dev 返回 EIP-712 域分隔符
     * 如果 chainId 发生变化（如分叉），会重新计算
     */
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _cachedChainId) {
            return _domainSeparator;
        }
        return _computeDomainSeparator();
    }

    // ============ 内部函数 ============

    function _transfer(address from, address to, uint256 value) internal {
        if (from == address(0)) revert();
        if (to == address(0)) revert();
        if (balanceOf[from] < value) {
            revert ERC20InsufficientBalance(from, balanceOf[from], value);
        }
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function _computeDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),      // 合约名称哈希
                keccak256(bytes("1")),       // 版本 "1" 的哈希
                block.chainid,
                address(this)
            )
        );
    }
}
