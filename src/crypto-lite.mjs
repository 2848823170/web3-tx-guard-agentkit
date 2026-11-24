import crypto from "node:crypto";

// Pure 24-round Keccak-256 (Ethereum standard 0x01 domain padding, NOT NIST SHA3-256 0x06)
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const MASK64 = 0xffffffffffffffffn;

function rotl64(x, n) {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

export function keccak256Hex(input) {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  const rate = 136;
  const padLen = rate - (bytes.length % rate);
  const msg = Buffer.alloc(bytes.length + padLen);
  bytes.copy(msg, 0);
  msg[bytes.length] = 0x01;
  msg[msg.length - 1] |= 0x80;

  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < msg.length; offset += rate) {
    for (let i = 0; i < 17; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) {
        lane |= BigInt(msg[offset + i * 8 + b]) << BigInt(8 * b);
      }
      state[i] ^= lane;
    }
    for (let round = 0; round < 24; round++) {
      const c = new Array(5).fill(0n);
      for (let x = 0; x < 5; x++) {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (let y = 0; y < 25; y += 5) state[x + y] = (state[x + y] ^ d) & MASK64;
      }
      let cur = state[1];
      for (let i = 0; i < 24; i++) {
        const j = PILN[i];
        const tmp = state[j];
        state[j] = rotl64(cur, ROTC[i]);
        cur = tmp;
      }
      for (let y = 0; y < 25; y += 5) {
        const row = [state[y], state[y + 1], state[y + 2], state[y + 3], state[y + 4]];
        for (let x = 0; x < 5; x++) {
          state[y + x] = (row[x] ^ ((~row[(x + 1) % 5] & MASK64) & row[(x + 2) % 5])) & MASK64;
        }
      }
      state[0] = (state[0] ^ RC[round]) & MASK64;
    }
  }

  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    const lane = state[i];
    for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((lane >> BigInt(8 * b)) & 0xffn);
  }
  return out.toString("hex");
}

export function toChecksumEvmAddress(addr) {
  const lower = addr.replace(/^0x/i, "").toLowerCase();
  const hash = keccak256Hex(lower);
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function decodeBase58(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    num = num * 58n + BigInt(idx);
  }
  const hex = num === 0n ? "" : num.toString(16).padStart(2, "0");
  const evenHex = hex.length % 2 === 1 ? "0" + hex : hex;
  const raw = evenHex ? Buffer.from(evenHex, "hex") : Buffer.alloc(0);
  let leadingZeros = 0;
  for (const ch of str) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  return Buffer.concat([Buffer.alloc(leadingZeros), raw]);
}

function crc16Xmodem(buf) {
  let crc = 0x0000;
  for (const byte of buf) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

export function localValidateAddress({ address, chain }) {
  const raw = String(address || "").trim();
  const warnings = [];
  if (!raw) return { valid: false, safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Empty address"] };

  // EVM
  if (/^0x[0-9a-fA-F]{40}$/.test(raw) || (chain && chain.toLowerCase() === "evm")) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(raw)) {
      return { valid: false, chain: "evm", safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Malformed EVM hex address"] };
    }
    const body = raw.slice(2);
    const checksummed = toChecksumEvmAddress(raw);
    const isMixed = body !== body.toLowerCase() && body !== body.toUpperCase();
    if (isMixed && raw !== checksummed) {
      return {
        valid: false,
        chain: "evm",
        canonicalAddress: checksummed,
        safeToTransact: false,
        riskLevel: "CRITICAL",
        warnings: [`EIP-55 checksum mismatch: expected ${checksummed}`],
      };
    }
    const bigVal = BigInt(raw);
    const isDead = raw.toLowerCase() === "0x000000000000000000000000000000000000dead";
    if (bigVal <= 0xffn || isDead) {
      return {
        valid: true,
        chain: "evm",
        canonicalAddress: checksummed,
        safeToTransact: false,
        riskLevel: "CRITICAL",
        warnings: ["Burn or EVM precompile address — funds will be permanently lost"],
      };
    }
    if (!isMixed) warnings.push("Unchecksummed EVM address normalized to EIP-55");
    return { valid: true, chain: "evm", canonicalAddress: checksummed, safeToTransact: true, riskLevel: "LOW", warnings };
  }

  // TON friendly EQ/UQ
  if (/^(EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46}$/.test(raw) || (chain && chain.toLowerCase() === "ton")) {
    const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(b64, "base64");
    if (buf.length !== 36) {
      return { valid: false, chain: "ton", safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Invalid TON friendly address length"] };
    }
    const expectedCrc = crc16Xmodem(buf.subarray(0, 34));
    const actualCrc = (buf[34] << 8) | buf[35];
    if (expectedCrc !== actualCrc) {
      return { valid: false, chain: "ton", safeToTransact: false, riskLevel: "CRITICAL", warnings: ["TON CRC16-XMODEM checksum mismatch"] };
    }
    const tag = buf[0];
    const isBounceable = tag === 0x11 || tag === 0x91;
    if (isBounceable) {
      warnings.push("Bounceable EQ... TON address: transfers to uninitialized wallets will bounce minus gas; prefer UQ... for user payouts");
    }
    return {
      valid: true,
      chain: "ton",
      canonicalAddress: raw,
      isBounceable,
      safeToTransact: true,
      riskLevel: isBounceable ? "MEDIUM" : "LOW",
      warnings,
    };
  }

  // Tron TRC-20
  if (raw.startsWith("T") && raw.length === 34) {
    const dec = decodeBase58(raw);
    if (!dec || dec.length !== 25 || dec[0] !== 0x41) {
      return { valid: false, chain: "tron", safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Invalid Tron prefix or length"] };
    }
    const chk = crypto.createHash("sha256").update(crypto.createHash("sha256").update(dec.subarray(0, 21)).digest()).digest();
    if (!chk.subarray(0, 4).equals(dec.subarray(21))) {
      return { valid: false, chain: "tron", safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Tron Base58Check checksum mismatch"] };
    }
    if (raw === "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb") {
      return { valid: true, chain: "tron", canonicalAddress: raw, safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Tron blackhole burn address"] };
    }
    return { valid: true, chain: "tron", canonicalAddress: raw, safeToTransact: true, riskLevel: "LOW", warnings };
  }

  // Solana
  const solDec = decodeBase58(raw);
  if (solDec && solDec.length === 32) {
    const burns = new Set(["11111111111111111111111111111111", "1nc1nerator11111111111111111111111111111111"]);
    if (burns.has(raw)) {
      return { valid: true, chain: "solana", canonicalAddress: raw, safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Solana system/incinerator burn address"] };
    }
    return { valid: true, chain: "solana", canonicalAddress: raw, safeToTransact: true, riskLevel: "LOW", warnings };
  }

  return { valid: false, safeToTransact: false, riskLevel: "CRITICAL", warnings: ["Unrecognized or invalid multichain address"] };
}

const MAX_UINT160 = (1n << 160n) - 1n;
const HALF_UINT256 = 1n << 255n;

export function localAuditCalldata({ to, value = "0", data = "0x" }) {
  const hex = String(data || "0x").replace(/^0x/i, "").toLowerCase();
  const valWei = String(value).startsWith("0x") ? BigInt(value) : BigInt(value || "0");
  const findings = [];
  let riskLevel = "LOW";

  if (hex.length < 8) {
    return { decodedMethod: "native_transfer", riskLevel: "LOW", safeToExecute: true, findings };
  }
  const selector = "0x" + hex.slice(0, 8);
  const argsHex = hex.slice(8);

  // ERC-20 approve(address,uint256) = 0x095ea7b3 | increaseAllowance = 0x39509351
  if ((selector === "0x095ea7b3" || selector === "0x39509351") && argsHex.length >= 128) {
    const spender = toChecksumEvmAddress("0x" + argsHex.slice(24, 64));
    const amount = BigInt("0x" + argsHex.slice(64, 128));
    if (amount >= HALF_UINT256) {
      riskLevel = "CRITICAL";
      findings.push(`Unlimited ERC-20 token approval (>= 2^255) granted to ${spender}`);
    }
    if (valWei > 0n) {
      riskLevel = "CRITICAL";
      findings.push(`Non-zero native ETH value (${valWei} wei) attached to token approval call`);
    }
    return { decodedMethod: "approve", selector, spender, riskLevel, safeToExecute: riskLevel !== "CRITICAL", findings };
  }

  // ERC-721/1155 setApprovalForAll(address,bool) = 0xa22cb465
  if (selector === "0xa22cb465" && argsHex.length >= 128) {
    const operator = toChecksumEvmAddress("0x" + argsHex.slice(24, 64));
    const approved = BigInt("0x" + argsHex.slice(64, 128)) !== 0n;
    if (approved) {
      riskLevel = "CRITICAL";
      findings.push(`setApprovalForAll(true) grants full collection drain rights to ${operator}`);
    }
    return { decodedMethod: "setApprovalForAll", selector, operator, riskLevel, safeToExecute: riskLevel !== "CRITICAL", findings };
  }

  // Uniswap V2 swapExactTokensForTokens (0x38ed1739) -> word 1 is amountOutMin
  if (selector === "0x38ed1739" && argsHex.length >= 128) {
    const amountOutMin = BigInt("0x" + argsHex.slice(64, 128));
    if (amountOutMin === 0n) {
      riskLevel = "CRITICAL";
      findings.push("Zero slippage protection (amountOutMin == 0) exposes swap to 100% MEV sandwich extraction");
    }
    return { decodedMethod: "swapExactTokensForTokens", selector, riskLevel, safeToExecute: riskLevel !== "CRITICAL", findings };
  }

  // Safe execTransaction (0x6a761202) -> word 3 is operation (1 == DELEGATECALL)
  if (selector === "0x6a761202" && argsHex.length >= 256) {
    const operation = BigInt("0x" + argsHex.slice(192, 256));
    if (operation === 1n) {
      riskLevel = "CRITICAL";
      findings.push("Safe execTransaction with operation=1 (DELEGATECALL) can overwrite Safe storage & owners");
    }
    return { decodedMethod: "execTransaction", selector, riskLevel, safeToExecute: riskLevel !== "CRITICAL", findings };
  }

  return { decodedMethod: "unknown_selector", selector, to, riskLevel, safeToExecute: true, findings };
}

export function localAuditEip712({ typedData }) {
  const td = typeof typedData === "string" ? JSON.parse(typedData) : typedData || {};
  const primaryType = String(td.primaryType || "");
  const message = td.message || {};
  const domain = td.domain || {};
  const findings = [];
  let riskLevel = "LOW";

  if (!domain.chainId && !domain.verifyingContract) {
    riskLevel = "HIGH";
    findings.push("EIP-712 domain lacks both chainId and verifyingContract (cross-chain/contract replay risk)");
  }

  // EIP-2612 Permit
  if (primaryType === "Permit") {
    const val = BigInt(String(message.value ?? "0"));
    if (val >= HALF_UINT256 || message.allowed === true) {
      riskLevel = "CRITICAL";
      findings.push(`Gasless EIP-2612 Permit grants unlimited allowance to spender ${message.spender}`);
    }
  }

  // Permit2 PermitSingle / PermitBatch
  if (primaryType === "PermitSingle" && message.details) {
    const amt = BigInt(String(message.details.amount ?? "0"));
    if (amt >= MAX_UINT160) {
      riskLevel = "CRITICAL";
      findings.push(`Permit2 PermitSingle grants MAX_UINT160 allowance to spender ${message.spender}`);
    }
  }

  // Seaport OrderComponents zero-consideration drain
  if (primaryType === "OrderComponents" && Array.isArray(message.offer)) {
    const offerer = String(message.offerer || "").toLowerCase();
    const consideration = Array.isArray(message.consideration) ? message.consideration : [];
    const sellerReceives = consideration.filter((c) => String(c.recipient || "").toLowerCase() === offerer && BigInt(String(c.startAmount ?? "0")) > 0n);
    if (message.offer.length > 0 && sellerReceives.length === 0) {
      riskLevel = "CRITICAL";
      findings.push("Seaport OrderComponents phishing drain: offer transfers assets while offerer receives 0 consideration");
    }
  }

  return { primaryType, riskLevel, safeToSign: riskLevel !== "CRITICAL", findings };
}
