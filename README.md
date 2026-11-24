# `web3-tx-guard-agentkit` — Pre-Sign Firewall & `x402` Base `USDC` SDK for Web3 Agents

[![CI](https://github.com/2848823170/web3-tx-guard-agentkit/actions/workflows/ci.yml/badge.svg)](https://github.com/2848823170/web3-tx-guard-agentkit/actions)

**Zero-dependency pre-execution transaction, calldata & EIP-712 signature firewall for `Coinbase AgentKit`, `ElizaOS`, `GOAT SDK`, and `viem` — powered by native `x402` Base Mainnet `USDC` (`$0.01/call`) + deterministic offline cryptographic fallback.**

- **Interactive Playground & Live Policy Simulator**: **[https://2848823170.github.io/web3-tx-guard-agentkit/](https://2848823170.github.io/web3-tx-guard-agentkit/)**
- **Live `x402` Base `USDC` Gateway (`0%` middleman fee)**: `https://nick-ebony-forth-sic.trycloudflare.com` ([OpenAPI 3.1](https://nick-ebony-forth-sic.trycloudflare.com/openapi.json) · [x402 Manifest](https://nick-ebony-forth-sic.trycloudflare.com/.well-known/x402.json))
- **Hosted MCP Servers**: [Glama Grade-A `web3-tx-guard-mcp`](https://glama.ai/mcp/servers/2848823170/web3-tx-guard-mcp) · [MCPize 6-Tool `x402` Server](https://mcpize.com/mcp/docuclean-ledger-mcp)

---

## Why Autonomous DeFi & Treasury Agents Need Pre-Sign Guardrails

Prompt injection, poisoned DEX quotes, or malformed LLM tool arguments routinely trick autonomous wallets into signing:
1. **Unlimited Token Approvals** (`ERC-20 approve >= 2^255`, `setApprovalForAll(true)`, `Permit2 MAX_UINT160`),
2. **Zero-Consideration `Seaport` / `EIP-2612` Blind-Signature Drains**,
3. **`amountOutMin == 0` MEV Sandwich Swaps** & **`Safe` `operation=1` (`DELEGATECALL`) Takeovers**,
4. **Irreversible Burn / Checksum / Bounce Traps** (`0x...dEaD`, corrupted EIP-55, Solana off-curve PDA confusion, TON `EQ...` uninitialized-wallet bounce).

`web3-tx-guard-agentkit` wraps your existing wallet or plugs directly into `Coinbase AgentKit`, `ElizaOS`, and `GOAT SDK` in **5 lines of code**.

---

## Quick Start

```bash
npm install github:2848823170/web3-tx-guard-agentkit
```

### 1. Wrap Any `viem` / `AgentKit` Wallet Before Signing

```js
import { TxGuardX402Client, wrapWalletWithTxGuard } from "web3-tx-guard-agentkit";

const guard = new TxGuardX402Client({
  maxAtomicUsdcPerCall: 20000n, // Hard $0.02 Base USDC cap per deep audit call
  eip3009Signer: async (typedData) => ({
    from: walletClient.account.address,
    signature: await walletClient.signTypedData(typedData),
  }),
});

const safeWallet = wrapWalletWithTxGuard(walletClient, guard);

// Automatically blocks unlimited approvals, burn addresses & Seaport drains BEFORE signing!
await safeWallet.sendTransaction({ to, value, data });
```

### 2. Drop Into `Coinbase AgentKit`, `ElizaOS`, or `GOAT SDK`

```js
import {
  TxGuardX402Client,
  createCoinbaseAgentKitActions,
  createElizaOsPlugin,
  createGoatPlugin,
} from "web3-tx-guard-agentkit";

const client = new TxGuardX402Client();

const agentKitProvider = createCoinbaseAgentKitActions(client); // getActions() -> 3 tools
const elizaPlugin = createElizaOsPlugin(client);                // character.plugins
const goatPlugin = createGoatPlugin(client);                    // getTools() -> 3 tools
```

---

## Built-In `x402` Spend-Policy Verification

Before signing any `HTTP 402` EIP-3009 `TransferWithAuthorization` challenge, `verifyX402QuoteSafety()` cryptographically enforces:
- Canonical Base Mainnet `USDC` contract (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, `eip155:8453`),
- Strict per-call micro-cap (`maxAtomicUsdcPerCall`, default `$0.02 USDC`),
- Optional `allowedPayTo` treasury allowlist.

## Verification

```bash
npm test
```
