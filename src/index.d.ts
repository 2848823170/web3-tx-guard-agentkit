export declare const BASE_MAINNET_USDC: string;
export declare const DEFAULT_X402_GATEWAY: string;
export declare const DEFAULT_X402_GATEWAY_URL: string;
export declare const FALLBACK_X402_GATEWAY_URL: string;
export declare const DEFAULT_MCPIZE_URL: string;
export declare const OFFICIAL_TREASURY_PAYTO: string;

export declare class TxGuardBlockedError extends Error {
  auditResult: Record<string, unknown>;
  constructor(message: string, auditResult: Record<string, unknown>);
}

export declare class X402PolicyViolationError extends Error {
  quote: Record<string, unknown>;
  constructor(message: string, quote: Record<string, unknown>);
}

export interface Eip3009SignatureResult {
  from: string;
  signature: string;
}

export interface TxGuardClientOptions {
  gatewayUrl?: string;
  eip3009Signer?: (typedData: Record<string, unknown>) => Promise<Eip3009SignatureResult>;
  maxAtomicUsdcPerCall?: bigint | number;
  allowedPayTo?: string[];
  offlineFallback?: boolean;
  fetchImpl?: typeof fetch;
}

export declare class TxGuardX402Client {
  constructor(options?: TxGuardClientOptions);
  validateAddress(params: { address: string; chain?: string }): Promise<Record<string, unknown>>;
  auditCalldata(params: { to: string; value?: string; data: string; chainId?: number }): Promise<Record<string, unknown>>;
  auditEip712(params: { typedData: Record<string, unknown> | string }): Promise<Record<string, unknown>>;
}

export declare function verifyX402QuoteSafety(
  quote: Record<string, unknown>,
  policy?: { maxAtomicUsdcPerCall?: bigint | number; allowedPayTo?: string[] }
): { payTo: string; amountAtomic: bigint; network: string };

export declare function wrapWalletWithTxGuard<T extends object>(
  wallet: T,
  client: TxGuardX402Client,
  options?: { blockOnHigh?: boolean }
): T;

export declare function createCoinbaseAgentKitActions(client: TxGuardX402Client): Record<string, unknown>;
export declare function createElizaOsPlugin(client: TxGuardX402Client): Record<string, unknown>;
export declare function createGoatPlugin(client: TxGuardX402Client): Record<string, unknown>;
