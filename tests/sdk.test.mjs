import test from "node:test";
import assert from "node:assert/strict";
import {
  BASE_MAINNET_USDC,
  OFFICIAL_TREASURY_PAYTO,
  TxGuardX402Client,
  TxGuardBlockedError,
  X402PolicyViolationError,
  verifyX402QuoteSafety,
  wrapWalletWithTxGuard,
  createCoinbaseAgentKitActions,
  createElizaOsPlugin,
  createGoatPlugin,
} from "../src/index.mjs";

test("1. verifyX402QuoteSafety enforces Base mainnet USDC, maxAtomicUsdcPerCall cap & allowedPayTo", () => {
  const validQuote = {
    network: "eip155:8453",
    asset: BASE_MAINNET_USDC,
    amount: "10000",
    payTo: OFFICIAL_TREASURY_PAYTO,
  };
  const ok = verifyX402QuoteSafety(validQuote, {
    maxAtomicUsdcPerCall: 20000n,
    allowedPayTo: [OFFICIAL_TREASURY_PAYTO],
  });
  assert.equal(ok.amountAtomic, 10000n);

  // Reject $50 rogue overcharge
  assert.throws(
    () => verifyX402QuoteSafety({ ...validQuote, amount: "50000000" }, { maxAtomicUsdcPerCall: 20000n }),
    X402PolicyViolationError
  );

  // Reject spoofed token contract
  assert.throws(
    () => verifyX402QuoteSafety({ ...validQuote, asset: "0x000000000000000000000000000000000000dead" }),
    X402PolicyViolationError
  );

  // Reject wrong chain
  assert.throws(
    () => verifyX402QuoteSafety({ ...validQuote, network: "eip155:84532" }),
    X402PolicyViolationError
  );
});

test("2. TxGuardX402Client negotiates HTTP 402 -> EIP-3009 X-PAYMENT header -> 200 OK end-to-end", async () => {
  let calls = 0;
  let capturedXPayment = null;

  const mockFetch = async (_url, init) => {
    calls++;
    if (calls === 1) {
      return {
        status: 402,
        ok: false,
        headers: new Map(),
        json: async () => ({
          x402Version: 1,
          accepts: [
            {
              scheme: "exact",
              network: "base",
              maxAmountRequired: "10000",
              asset: BASE_MAINNET_USDC,
              payTo: OFFICIAL_TREASURY_PAYTO,
              maxTimeoutSeconds: 300,
              extra: { name: "USD Coin", version: "2" },
            },
          ],
        }),
      };
    }
    capturedXPayment = init.headers["x-payment"];
    return {
      status: 200,
      ok: true,
      json: async () => ({ valid: true, chain: "evm", canonicalAddress: OFFICIAL_TREASURY_PAYTO, safeToTransact: true, riskLevel: "LOW" }),
    };
  };

  const client = new TxGuardX402Client({
    gatewayUrl: "https://example-x402.test",
    fetchImpl: mockFetch,
    allowedPayTo: [OFFICIAL_TREASURY_PAYTO],
    eip3009Signer: async (typedData) => {
      assert.equal(typedData.primaryType, "TransferWithAuthorization");
      assert.equal(typedData.domain.verifyingContract, BASE_MAINNET_USDC);
      assert.equal(typedData.message.to, OFFICIAL_TREASURY_PAYTO);
      assert.equal(typedData.message.value, "10000");
      return { from: "0x1111111111111111111111111111111111111111", signature: "0xdeadbeef" };
    },
  });

  const res = await client.validateAddress({ address: OFFICIAL_TREASURY_PAYTO });
  assert.equal(calls, 2);
  assert.equal(res.safeToTransact, true);
  const decodedPayment = JSON.parse(Buffer.from(capturedXPayment, "base64").toString("utf8"));
  assert.equal(decodedPayment.x402Version, 1);
  assert.equal(decodedPayment.payload.authorization.to, OFFICIAL_TREASURY_PAYTO);
});

test("3. wrapWalletWithTxGuard intercepts unlimited ERC-20 approve, burn addresses & Seaport 0-consideration drains", async () => {
  const offlineClient = new TxGuardX402Client({
    gatewayUrl: "http://127.0.0.1:1",
    offlineFallback: true,
    fetchImpl: async () => {
      throw new Error("offline");
    },
  });

  let sentCount = 0;
  let signedCount = 0;
  const rawWallet = {
    sendTransaction: async (tx) => {
      sentCount++;
      return "0xtxhash_ok";
    },
    signTypedData: async (td) => {
      signedCount++;
      return "0xsig_ok";
    },
  };

  const guarded = wrapWalletWithTxGuard(rawWallet, offlineClient);

  // Clean transfer to checksummed Boss EVM address succeeds
  const cleanHash = await guarded.sendTransaction({
    to: OFFICIAL_TREASURY_PAYTO,
    value: "1000000",
    data: "0x",
  });
  assert.equal(cleanHash, "0xtxhash_ok");
  assert.equal(sentCount, 1);

  // Burn address blocked before signing
  await assert.rejects(
    () => guarded.sendTransaction({ to: "0x000000000000000000000000000000000000dEaD", value: "100" }),
    TxGuardBlockedError
  );

  // Unlimited ERC-20 approve(attacker, MAX_UINT256) blocked before signing
  const maxApproveData =
    "0x095ea7b3" +
    "0000000000000000000000002222222222222222222222222222222222222222" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  await assert.rejects(
    () => guarded.sendTransaction({ to: BASE_MAINNET_USDC, data: maxApproveData }),
    TxGuardBlockedError
  );
  assert.equal(sentCount, 1);

  // Seaport OrderComponents zero-consideration phishing signature blocked
  await assert.rejects(
    () =>
      guarded.signTypedData({
        domain: { name: "Seaport", version: "1.5", chainId: 1, verifyingContract: "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC" },
        primaryType: "OrderComponents",
        message: {
          offerer: "0x1111111111111111111111111111111111111111",
          offer: [{ itemType: 2, token: "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", startAmount: "1" }],
          consideration: [{ itemType: 0, recipient: "0x9999999999999999999999999999999999999999", startAmount: "0" }],
        },
      }),
    TxGuardBlockedError
  );
  assert.equal(signedCount, 0);
});

test("4. Coinbase AgentKit, ElizaOS, and GOAT SDK adapters expose working pre-flight security actions", async () => {
  const client = new TxGuardX402Client({
    gatewayUrl: "http://127.0.0.1:1",
    offlineFallback: true,
    fetchImpl: async () => {
      throw new Error("offline");
    },
  });

  // Coinbase AgentKit
  const cbProvider = createCoinbaseAgentKitActions(client);
  const cbActions = cbProvider.getActions();
  assert.equal(cbActions.length, 3);
  const tronOut = JSON.parse(await cbActions[0].invoke({}, { address: "TScN3VSpNyxPYvCsvSaze2HFkFFuCAXgYE" }));
  assert.equal(tronOut.valid, true);
  assert.equal(tronOut.chain, "tron");

  // ElizaOS
  const eliza = createElizaOsPlugin(client);
  assert.equal(eliza.name, "web3-tx-guard");
  const solOut = await eliza.actions[0].handler({}, { content: { address: "2h68rTXHZW65UWnM1uXnE5ABD4Tj62qN14vFZvVaX3bC" } });
  assert.equal(solOut.valid, true);
  assert.equal(solOut.chain, "solana");

  // GOAT SDK
  const goat = createGoatPlugin(client);
  const tools = goat.getTools();
  assert.equal(tools.length, 3);
  const tonBounce = await tools[0].execute({ address: "EQAe3nzr65L7AOaFr5Q2_Ag7XpuAIXijA-qMdDdeJ-57yOo9" });
  assert.equal(tonBounce.valid, true);
  assert.equal(tonBounce.isBounceable, true);
  assert.equal(tonBounce.riskLevel, "MEDIUM");
});
