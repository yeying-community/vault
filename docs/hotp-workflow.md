# HOTP 工作原理

本文沉淀 HOTP（HMAC-based One-Time Password，基于 HMAC 的一次性密码）的核心原理，并给出从“密钥下发”到“验证码校验与计数器推进”的完整流程。

## 1. 核心要素
- `K`：共享密钥（种子），由服务端生成并与用户绑定。
- `C`：事件计数器（Counter），每生成或成功校验一次会推进。
- `Digits`：验证码位数（常见 `6` 位）。
- `H`：哈希算法（RFC 4226 标准为 `SHA-1`）。

## 2. 生成公式
1. 将计数器 `C` 转为 8 字节大端整数。
2. 计算摘要：`HS = HMAC(H, K, C)`
3. 动态截断（Dynamic Truncation）：
   - `offset = low4bits(HS[lastByte])`
   - `P = HS[offset : offset+4]`
   - `Snum = P & 0x7fffffff`（得到 31-bit 正整数）
4. 计算 OTP：`OTP = Snum mod 10^Digits`
5. 左侧补零到固定长度（例如 `6` 位）

标准表达式：`HOTP(K, C) = Truncate(HMAC-SHA-1(K, C)) mod 10^Digits`

## 3. 详细时序图（Mermaid）
```mermaid
sequenceDiagram
    autonumber
    actor U as 用户
    participant A as 认证器
    participant W as 登录页面
    participant S as 服务端
    participant D as 数据存储

    Note over U,D: 首次绑定
    S->>S: 生成随机共享密钥 K
    S->>D: 初始化并保存 C_server，通常为 0
    S-->>W: 返回 otpauth URI 或二维码
    W-->>U: 展示二维码
    U->>A: 扫码导入 K 并初始化 C_client
    A-->>U: 绑定成功

    Note over U,D: 日常登录与校验
    U->>A: 触发生成 OTP
    A->>A: 用 C_client 计算 HOTP
    A->>A: C_client 自增 1
    A-->>U: 显示 OTP
    U->>W: 输入账号密码和 OTP
    W->>S: 提交登录请求
    S->>D: 读取 K 与 C_server
    D-->>S: 返回 K 与 C_server
    loop 每个 C，范围 C_server 到 C_server+s
        S->>S: 计算候选 HOTP
    end
    alt 命中某个候选 OTP
        S->>S: 得到命中计数器 C_match
        S->>D: 推进 C_server 为 C_match + 1
        D-->>S: 更新成功
        S-->>W: 校验通过并发放会话
        W-->>U: 登录成功
    else 未命中
        S-->>W: 校验失败
        W-->>U: 提示重试
    end
```

## 4. 校验侧最佳实践
- 成功后务必推进服务端计数器，防止 OTP 重放。
- 仅允许有限前瞻窗口（如 `s=10`），平衡容错与安全。
- 对失败尝试做限流与锁定，降低暴力猜测风险。
- 使用常量时间比较，减少时序侧信道风险。
- 对“计数器漂移过大”提供安全的重新同步流程。

## 5. 与 TOTP 的关系
- HOTP 基于“事件计数器”，每次事件触发都推进计数器。
- TOTP 可视为将 HOTP 的 `Counter` 替换为“时间片计数器”后的变种。
