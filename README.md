# Web Authenticator

基于 WebAuthn PRF + Web Crypto 的 Web 版 TOTP Authenticator。TOTP 种子只在浏览器端加密保存，解锁依赖 Passkey 生物认证。

## 技术选型
- 前端：原生 JavaScript + Web Crypto + WebAuthn
- 后端：Node.js + Express + @simplewebauthn/server

## 本地运行
```bash
npm install
npm run start
```
打开 `http://localhost:3000`。

## 生产环境要点
- 使用 HTTPS，并设置 `ORIGIN` 与 `RP_ID`
  - `ORIGIN=https://your-domain` 
  - `RP_ID=your-domain`
- 设置 `SESSION_SECRET`
- 依赖 WebAuthn PRF 扩展（当前 Chrome/Edge 支持较好）

## 数据位置
- Passkey 元数据：`data/webauthn.json`
- 加密 Vault：浏览器 IndexedDB（`web-authenticator`）
