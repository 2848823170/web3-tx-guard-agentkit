import crypto from "node:crypto";
import { localValidateAddress, localAuditCalldata, localAuditEip712 } from "./crypto-lite.mjs";

export const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const DEFAULT_X402_GATEWAY = "https://nick-ebony-forth-sic.trycloudflare.com";
export const DEFAULT_MCPIZE_URL = "https://docuclean-ledger-mcp.mcpize.run/mcp";
export const OFFICIAL_TREASURY_PAYTO = "0xfEbDbB880C7f323c145d61683874a45540208a68";

export class TxGuardBlockedError extends Error {
  constructor(message, auditResult) {
    super(message);
    this.name = "TxGuardBlockedError";
    this.auditResult = auditResult;
  }
}

export class X402PolicyViolationError extends Error {
  constructor(message, quote) {
    super(message);
    this.name = "X402PolicyViolationError";
    this.quote = quote;
  }
}

/**
 * Validates an incoming HTTP 402 payment requirement before signing EIP-3009 USDC authorization,
 * preventing malicious/spoofed endpoints from overcharging or switching tokens/chains.
 */
export function verifyX402QuoteSafety(quote, policy = {}) {
  const maxAtomic = BigInt(policy.maxAtomicUsdcPerCall ?? 20000n); // default $0.02 USDC cap
  const network = String(quote?.network || "");
  if (network !== "base" && network !== "eip155:8453") {
    throw new X402PolicyViolationError(`Disallowed x402 network '${network}' (expected Base mainnet)`, quote);
  }
  const asset = String(quote?.asset || "").toLowerCase();
  if (asset !== BASE_MAINNET_USDC.toLowerCase()) {
    throw new X402PolicyViolationError(`Untrusted x402 token contract '${quote?.asset}' (expected Base USDC)`, quote);
  }
  const rawAmt = BigInt(String(quote?.maxAmountRequired ?? quote?.amount ?? "0"));
  if (rawAmt <= 0n || rawAmt > maxAtomic) {
    throw new X402PolicyViolationError(`x402 amount ${rawAmt} exceeds policy cap ${maxAtomic}`, quote);
  }
  if (Array.isArray(policy.allowedPayTo) && policy.allowedPayTo.length > 0) {
    const allowedSet = new Set(policy.allowedPayTo.map((a) => a.toLowerCase()));
    if (!allowedSet.has(String(quote?.payTo || "").toLowerCase())) {
      throw new X402PolicyViolationError(`payTo '${quote?.payTo}' is not in allowedPayTo policy list`, quote);
    }
  }
  return { payTo: quote.payTo, amountAtomic: rawAmt, network };
}

export class TxGuardX402Client {
  /**
   * @param {object} [options]
   * @param {string} [options.gatewayUrl] Base URL of the x402 Web3 Security Gateway
   * @param {(typedData: object) => Promise<{ from: string, signature: string }>} [options.eip3009Signer] Optional Base USDC EIP-3009 signer
   * @param {bigint|number} [options.maxAtomicUsdcPerCall] Max atomic USDC per request (default 20000 = $0.02)
   * @param {string[]} [options.allowedPayTo] Optional recipient allowlist
   * @param {boolean} [options.offlineFallback] Fall back to deterministic local engine when offline or unpaid (default true)
   * @param {typeof fetch} [options.fetchImpl] Custom fetch implementation for testing
   */
  constructor(options = {}) {
    this.gatewayUrl = String(options.gatewayUrl || DEFAULT_X402_GATEWAY).replace(/\/+$/, "");
    this.eip3009Signer = options.eip3009Signer || null;
    this.maxAtomicUsdcPerCall = BigInt(options.maxAtomicUsdcPerCall ?? 20000n);
    this.allowedPayTo = options.allowedPayTo || null;
    this.offlineFallback = options.offlineFallback !== false;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  async _buildX402PaymentHeader(quote) {
    const checked = verifyX402QuoteSafety(quote, {
      maxAtomicUsdcPerCall: this.maxAtomicUsdcPerCall,
      allowedPayTo: this.allowedPayTo,
    });
    const nowSec = Math.floor(Date.now() / 1000);
    const nonceHex = "0x" + crypto.randomBytes(32).toString("hex");
    const validAfter = "0";
    const validBefore = String(nowSec + Number(quote.maxTimeoutSeconds || 300));
    const valueStr = checked.amountAtomic.toString();

    const typedData = {
      domain: {
        name: quote.extra?.name || "USD Coin",
        version: quote.extra?.version || "2",
        chainId: 8453,
        verifyingContract: BASE_MAINNET_USDC,
      },
      types: {
        TransferWithAuthorization: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      primaryType: "TransferWithAuthorization",
      message: {
        to: checked.payTo,
        value: valueStr,
        validAfter,
        validBefore,
        nonce: nonceHex,
      },
    };

    const signed = await this.eip3009Signer(typedData);
    const authorization = {
      from: signed.from,
      to: checked.payTo,
      value: valueStr,
      validAfter,
      validBefore,
      nonce: nonceHex,
    };

    const v1Payload = {
      x402Version: 1,
      scheme: "exact",
      network: "base",
      payload: { signature: signed.signature, authorization },
    };
    return Buffer.from(JSON.stringify(v1Payload), "utf8").toString("base64");
  }

  async _postWithX402(routePath, body, localFn) {
    const url = `${this.gatewayUrl}${routePath}`;
    try {
      const resp1 = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(body),
      });

      if (resp1.status === 200) {
        return await resp1.json();
      }

      if (resp1.status === 402) {
        let quote = null;
        const v2Hdr = resp1.headers?.get?.("payment-required");
        if (v2Hdr) {
          try {
            const parsedV2 = JSON.parse(Buffer.from(v2Hdr, "base64").toString("utf8"));
            quote = parsedV2.accepts?.[0] || null;
          } catch (_) {}
        }
        const json402 = await resp1.json().catch(() => ({}));
        if (!quote && Array.isArray(json402.accepts)) {
          quote = json402.accepts[0];
        }

        if (this.eip3009Signer && quote) {
          const xPaymentB64 = await this._buildX402PaymentHeader(quote);
          const resp2 = await this.fetchImpl(url, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json",
              "x-payment": xPaymentB64,
            },
            body: JSON.stringify(body),
          });
          if (resp2.ok) return await resp2.json();
          const errTxt = await resp2.text().catch(() => "");
          throw new Error(`Paid x402 retry failed (${resp2.status}): ${errTxt}`);
        }

        if (this.offlineFallback) {
          return { ...localFn(body), mode: "local_deterministic_fallback", x402QuoteAvailable: Boolean(quote) };
        }
        throw new Error("HTTP 402 Payment Required and no eip3009Signer configured");
      }

      const badBody = await resp1.text().catch(() => "");
      throw new Error(`Gateway returned HTTP ${resp1.status}: ${badBody}`);
    } catch (err) {
      if (err instanceof X402PolicyViolationError) throw err;
      if (this.offlineFallback) {
        return { ...localFn(body), mode: "local_deterministic_fallback" };
      }
      throw err;
    }
  }

  async validateAddress(params) {
    return this._postWithX402("/api/v1/validate-address", params, localValidateAddress);
  }

  async auditCalldata(params) {
    return this._postWithX402("/api/v1/audit-calldata", params, localAuditCalldata);
  }

  async auditEip712(params) {
    return this._postWithX402("/api/v1/audit-eip712", params, localAuditEip712);
  }
}
