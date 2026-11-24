import { TxGuardBlockedError } from "./x402-client.mjs";

function isCriticalResult(res, blockOnHigh = false) {
  const level = String(res?.riskLevel || res?.result?.riskLevel || "LOW").toUpperCase();
  if (level === "CRITICAL") return true;
  if (blockOnHigh && level === "HIGH") return true;
  if (res?.safeToTransact === false || res?.safeToExecute === false || res?.safeToSign === false) return true;
  return false;
}

/**
 * Wraps any `viem` WalletClient or Coinbase AgentKit EVM WalletProvider so every
 * `sendTransaction` and `signTypedData` call passes pre-flight calldata / EIP-712 verification
 * BEFORE touching the agent's private key.
 */
export function wrapWalletWithTxGuard(wallet, client, options = {}) {
  const blockOnHigh = Boolean(options.blockOnHigh);
  return new Proxy(wallet, {
    get(target, prop, receiver) {
      const orig = Reflect.get(target, prop, receiver);
      if (prop === "sendTransaction" && typeof orig === "function") {
        return async function guardedSendTransaction(txReq, ...rest) {
          if (txReq?.to) {
            const addrCheck = await client.validateAddress({ address: txReq.to, chain: "evm" });
            if (isCriticalResult(addrCheck, blockOnHigh)) {
              throw new TxGuardBlockedError(
                `Blocked transaction to unsafe recipient ${txReq.to}: ${(addrCheck.warnings || []).join("; ")}`,
                addrCheck
              );
            }
          }
          if (txReq?.data && txReq.data !== "0x") {
            const cdCheck = await client.auditCalldata({
              to: txReq.to,
              value: txReq.value ? String(txReq.value) : "0",
              data: txReq.data,
              chainId: txReq.chainId || 8453,
            });
            if (isCriticalResult(cdCheck, blockOnHigh)) {
              throw new TxGuardBlockedError(
                `Blocked dangerous EVM calldata (${cdCheck.decodedMethod || cdCheck.selector}): ${(cdCheck.findings || []).join("; ")}`,
                cdCheck
              );
            }
          }
          return orig.call(target, txReq, ...rest);
        };
      }

      if (prop === "signTypedData" && typeof orig === "function") {
        return async function guardedSignTypedData(typedData, ...rest) {
          const sigCheck = await client.auditEip712({ typedData });
          if (isCriticalResult(sigCheck, blockOnHigh)) {
            throw new TxGuardBlockedError(
              `Blocked dangerous EIP-712 signature (${sigCheck.primaryType}): ${(sigCheck.findings || []).join("; ")}`,
              sigCheck
            );
          }
          return orig.call(target, typedData, ...rest);
        };
      }

      return typeof orig === "function" ? orig.bind(target) : orig;
    },
  });
}

/**
 * Coinbase AgentKit ActionProvider-compatible factory (`getActions()`).
 */
export function createCoinbaseAgentKitActions(client) {
  return {
    name: "web3-tx-guard",
    supportsNetwork: () => true,
    getActions() {
      return [
        {
          name: "tx_guard_validate_address",
          description:
            "Cryptographically validate a multichain recipient address (EVM EIP-55, Solana PDA vs wallet, TON EQ/UQ bounce trap, Tron, Bitcoin, XRPL) before sending funds.",
          schema: {
            type: "object",
            required: ["address"],
            properties: {
              address: { type: "string", description: "Target wallet or contract address" },
              chain: { type: "string", description: "Optional ecosystem hint (evm, solana, ton, tron, bitcoin, xrpl)" },
            },
          },
          invoke: async (_walletProvider, args) => JSON.stringify(await client.validateAddress(args)),
        },
        {
          name: "tx_guard_audit_calldata",
          description:
            "Decode and audit raw EVM transaction calldata (ERC-20/721 approvals, Permit2, Uniswap 0-slippage sandwich risk, recursive Multicall, Safe DELEGATECALL) before signing.",
          schema: {
            type: "object",
            required: ["to", "data"],
            properties: {
              to: { type: "string" },
              value: { type: "string" },
              data: { type: "string" },
              chainId: { type: "number" },
            },
          },
          invoke: async (_walletProvider, args) => JSON.stringify(await client.auditCalldata(args)),
        },
        {
          name: "tx_guard_audit_eip712",
          description:
            "Audit off-chain EIP-712 typed data (Permit, Permit2, Seaport zero-consideration drains, EIP-3009) before calling signTypedData.",
          schema: {
            type: "object",
            required: ["typedData"],
            properties: {
              typedData: { type: "object" },
            },
          },
          invoke: async (_walletProvider, args) => JSON.stringify(await client.auditEip712(args)),
        },
      ];
    },
  };
}

/**
 * ElizaOS (`@elizaos/core`) Plugin factory (`character.plugins`).
 */
export function createElizaOsPlugin(client) {
  return {
    name: "web3-tx-guard",
    description: "Pre-execution multichain address, EVM calldata, and EIP-712 signature firewall powered by x402 Base USDC",
    actions: [
      {
        name: "VERIFY_MULTICHAIN_ADDRESS",
        similes: ["CHECK_WALLET_ADDRESS", "VALIDATE_RECIPIENT", "AUDIT_ADDRESS"],
        description: "Verify cryptographic checksum, burn-trap status, and bounce/PDA safety of any Web3 address before transfer",
        validate: async (_runtime, message) => Boolean(message?.content?.address || message?.content?.text),
        handler: async (_runtime, message, _state, _options, callback) => {
          const address = message.content?.address || String(message.content?.text || "").trim().split(/\s+/).pop();
          const res = await client.validateAddress({ address, chain: message.content?.chain });
          if (callback) await callback({ text: JSON.stringify(res), content: res });
          return res;
        },
        examples: [],
      },
      {
        name: "AUDIT_EVM_TRANSACTION",
        similes: ["CHECK_CALLDATA", "SCAN_TX_HEX", "VERIFY_APPROVAL"],
        description: "Decode and risk-score raw EVM transaction calldata before wallet execution",
        validate: async (_runtime, message) => Boolean(message?.content?.data),
        handler: async (_runtime, message, _state, _options, callback) => {
          const res = await client.auditCalldata({
            to: message.content.to,
            value: message.content.value || "0",
            data: message.content.data,
            chainId: message.content.chainId || 8453,
          });
          if (callback) await callback({ text: JSON.stringify(res), content: res });
          return res;
        },
        examples: [],
      },
    ],
    evaluators: [],
    providers: [],
  };
}

/**
 * GOAT SDK (`@goat-sdk/core`) Plugin factory.
 */
export function createGoatPlugin(client) {
  return {
    name: "web3-tx-guard",
    supportsChain: () => true,
    getTools() {
      return [
        {
          name: "tx_guard_validate_address",
          description: "Validate checksum and burn/bounce safety across EVM, Solana, TON, Tron, Bitcoin, and XRPL",
          parameters: { type: "object", required: ["address"], properties: { address: { type: "string" }, chain: { type: "string" } } },
          execute: (params) => client.validateAddress(params),
        },
        {
          name: "tx_guard_audit_calldata",
          description: "Audit EVM transaction calldata for unlimited approvals, zero-slippage swaps, and Safe DELEGATECALL",
          parameters: { type: "object", required: ["to", "data"], properties: { to: { type: "string" }, value: { type: "string" }, data: { type: "string" } } },
          execute: (params) => client.auditCalldata(params),
        },
        {
          name: "tx_guard_audit_eip712",
          description: "Audit EIP-712 typedData payloads for Permit2 and Seaport zero-consideration drains",
          parameters: { type: "object", required: ["typedData"], properties: { typedData: { type: "object" } } },
          execute: (params) => client.auditEip712(params),
        },
      ];
    },
  };
}
