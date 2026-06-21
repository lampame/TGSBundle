"use strict";
/**
 * crypto.js — Patched version of telegram/crypto/crypto.js
 *
 * Adds pure-JS fallback for SHA-1, SHA-256, SHA-512, HMAC-SHA512, PBKDF2
 * when self.crypto.subtle is unavailable (HTTP context, older Smart TVs, etc.)
 *
 * Original: https://github.com/gram-js/gramjs/blob/develop/crypto/crypto.ts
 */

var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Hash = exports.CTR = exports.Counter = void 0;
exports.createDecipheriv = createDecipheriv;
exports.createCipheriv = createCipheriv;
exports.randomBytes = randomBytes;
exports.pbkdf2Sync = pbkdf2Sync;
exports.createHash = createHash;

const aes_1 = __importDefault(require("@cryptography/aes"));
const { i2ab, ab2i } = require("telegram/crypto/converters");
const { getWords } = require("telegram/crypto/words");

// ─── Helpers ─────────────────────────────────────────────────────

function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function concatBytes(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
}

function bufToBytes(buf) {
    if (buf instanceof Uint8Array) return buf;
    if (buf && buf.buffer) return new Uint8Array(buf);
    return new Uint8Array(buf);
}

// ─── Pure-JS SHA-1 ───────────────────────────────────────────────

function sha1(data) {
    const msg = bufToBytes(data);
    const bitLen = msg.length * 8;

    // Padding: append 0x80, then zeros (mod 512 = 448), then 64-bit length
    const padLen = ((448 - (bitLen + 1) % 512) % 512 + 512) % 512;
    const paddedLen = msg.length + 1 + Math.floor(padLen / 8) + 8;
    const padded = new Uint8Array(paddedLen);
    padded.set(msg);
    padded[msg.length] = 0x80;
    const hi = Math.floor(bitLen / 0x100000000) & 0xffffffff;
    const lo = bitLen >>> 0;
    padded[paddedLen - 8] = (hi >>> 24) & 0xff;
    padded[paddedLen - 7] = (hi >>> 16) & 0xff;
    padded[paddedLen - 6] = (hi >>> 8) & 0xff;
    padded[paddedLen - 5] = hi & 0xff;
    padded[paddedLen - 4] = (lo >>> 24) & 0xff;
    padded[paddedLen - 3] = (lo >>> 16) & 0xff;
    padded[paddedLen - 2] = (lo >>> 8) & 0xff;
    padded[paddedLen - 1] = lo & 0xff;

    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const W = new Uint32Array(80);

    for (let offset = 0; offset < paddedLen; offset += 64) {
        for (let t = 0; t < 16; t++) {
            const i = offset + t * 4;
            W[t] = (padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3];
        }
        for (let t = 16; t < 80; t++) {
            W[t] = rotr(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 31);
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4;

        for (let t = 0; t < 80; t++) {
            let f, k;
            if (t < 20)       { f = (b & c) | (~b & d); k = 0x5a827999; }
            else if (t < 40)  { f = b ^ c ^ d;         k = 0x6ed9eba1; }
            else if (t < 60)  { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else              { f = b ^ c ^ d;         k = 0xca62c1d6; }

            const temp = (rotr(a, 27) + f + e + k + W[t]) >>> 0;
            e = d; d = c; c = rotr(b, 2); b = a; a = temp;
        }

        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }

    const H = new Uint32Array([h0, h1, h2, h3, h4]);
    const result = new Uint8Array(20);
    for (let i = 0; i < 5; i++) {
        result[i * 4] = (H[i] >>> 24) & 0xff;
        result[i * 4 + 1] = (H[i] >>> 16) & 0xff;
        result[i * 4 + 2] = (H[i] >>> 8) & 0xff;
        result[i * 4 + 3] = H[i] & 0xff;
    }
    return Buffer.from(result);
}

// ─── Pure-JS SHA-256 ─────────────────────────────────────────────

const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

const SHA256_H0 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

function sha256(data) {
    const msg = bufToBytes(data);
    const bitLen = msg.length * 8;

    const padLen = ((448 - (bitLen + 1) % 512) % 512 + 512) % 512;
    const paddedLen = msg.length + 1 + Math.floor(padLen / 8) + 8;
    const padded = new Uint8Array(paddedLen);
    padded.set(msg);
    padded[msg.length] = 0x80;
    const hi = Math.floor(bitLen / 0x100000000) & 0xffffffff;
    const lo = bitLen >>> 0;
    padded[paddedLen - 8] = (hi >>> 24) & 0xff;
    padded[paddedLen - 7] = (hi >>> 16) & 0xff;
    padded[paddedLen - 6] = (hi >>> 8) & 0xff;
    padded[paddedLen - 5] = hi & 0xff;
    padded[paddedLen - 4] = (lo >>> 24) & 0xff;
    padded[paddedLen - 3] = (lo >>> 16) & 0xff;
    padded[paddedLen - 2] = (lo >>> 8) & 0xff;
    padded[paddedLen - 1] = lo & 0xff;

    const H = new Uint32Array(SHA256_H0);
    const W = new Uint32Array(64);

    for (let offset = 0; offset < paddedLen; offset += 64) {
        for (let t = 0; t < 16; t++) {
            const i = offset + t * 4;
            W[t] = (padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3];
        }
        for (let t = 16; t < 64; t++) {
            const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
        }

        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];

        for (let t = 0; t < 64; t++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ ((~e) & g);
            const temp1 = (h + S1 + ch + SHA256_K[t] + W[t]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + temp1) >>> 0;
            d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }

        H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    const result = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
        result[i * 4] = (H[i] >>> 24) & 0xff;
        result[i * 4 + 1] = (H[i] >>> 16) & 0xff;
        result[i * 4 + 2] = (H[i] >>> 8) & 0xff;
        result[i * 4 + 3] = H[i] & 0xff;
    }
    return Buffer.from(result);
}

// ─── Pure-JS SHA-512 (BigInt-based) ──────────────────────────────

const sha512_K = [
    0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn,
    0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n,
    0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n, 0xd807aa98a3030242n,
    0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n,
    0xc19bf174cf692694n, 0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n,
    0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 0x2de92c6f592b0275n,
    0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
    0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn,
    0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n,
    0x06ca6351e003826fn, 0x142929670a0e6e70n, 0x27b70a8546d22ffcn,
    0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
    0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n,
    0x92722c851482353bn, 0xa2bfe8a14cf10364n, 0xa81a664bbc423001n,
    0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n,
    0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n,
    0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn,
    0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n, 0x748f82ee5defb2fcn,
    0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
    0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n,
    0xc67178f2e372532bn, 0xca273eceea26619cn, 0xd186b8c721c0c207n,
    0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban,
    0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
    0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn,
    0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an,
    0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

const sha512_H0 = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn,
    0xa54ff53a5f1d36f1n, 0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
    0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

function sha512Ror(x, n) {
    return (x >> BigInt(n)) | (x << (64n - BigInt(n)));
}

function sha512(data) {
    const msg = bufToBytes(data);
    const bitLenBig = BigInt(msg.length * 8);

    // SHA-512 block = 1024 bits = 128 bytes
    // Padding: 0x80 + zeros until (msg_len + 1 + K + 16) % 128 == 0
    const padZeroBytes = (128 - ((msg.length + 1 + 16) % 128)) % 128;
    const paddedLen = msg.length + 1 + padZeroBytes + 16;
    const padded = new Uint8Array(paddedLen);
    padded.set(msg);
    padded[msg.length] = 0x80;

    // Write 128-bit big-endian length
    for (let i = 0; i < 16; i++) {
        padded[paddedLen - 16 + i] = Number((bitLenBig >> BigInt(120 - i * 8)) & 0xffn);
    }

    const H = sha512_H0.slice();
    const W = new Array(80);

    for (let offset = 0; offset < paddedLen; offset += 128) {
        for (let t = 0; t < 16; t++) {
            const i = offset + t * 8;
            W[t] = 0n;
            for (let b = 0; b < 8; b++) {
                W[t] = (W[t] << 8n) | BigInt(padded[i + b]);
            }
        }
        for (let t = 16; t < 80; t++) {
            const s0 = sha512Ror(W[t - 15], 1) ^ sha512Ror(W[t - 15], 8) ^ (W[t - 15] >> 7n);
            const s1 = sha512Ror(W[t - 2], 19) ^ sha512Ror(W[t - 2], 61) ^ (W[t - 2] >> 6n);
            W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & 0xffffffffffffffffn;
        }

        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];

        for (let t = 0; t < 80; t++) {
            const S1 = sha512Ror(e, 14) ^ sha512Ror(e, 18) ^ sha512Ror(e, 41);
            const ch = (e & f) ^ ((~e) & g);
            const temp1 = (h + S1 + ch + sha512_K[t] + W[t]) & 0xffffffffffffffffn;
            const S0 = sha512Ror(a, 28) ^ sha512Ror(a, 34) ^ sha512Ror(a, 39);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) & 0xffffffffffffffffn;

            h = g; g = f; f = e;
            e = (d + temp1) & 0xffffffffffffffffn;
            d = c; c = b; b = a;
            a = (temp1 + temp2) & 0xffffffffffffffffn;
        }

        H[0] = (H[0] + a) & 0xffffffffffffffffn;
        H[1] = (H[1] + b) & 0xffffffffffffffffn;
        H[2] = (H[2] + c) & 0xffffffffffffffffn;
        H[3] = (H[3] + d) & 0xffffffffffffffffn;
        H[4] = (H[4] + e) & 0xffffffffffffffffn;
        H[5] = (H[5] + f) & 0xffffffffffffffffn;
        H[6] = (H[6] + g) & 0xffffffffffffffffn;
        H[7] = (H[7] + h) & 0xffffffffffffffffn;
    }

    // Convert BigInts to bytes
    const result = new Uint8Array(64);
    for (let i = 0; i < 8; i++) {
        for (let b = 0; b < 8; b++) {
            result[i * 8 + b] = Number((H[i] >> BigInt(56 - b * 8)) & 0xffn);
        }
    }
    return Buffer.from(result);
}

// ─── HMAC-SHA512 ─────────────────────────────────────────────────

function hmacSha512(key, data) {
    const blockSize = 128;
    const keyBytes = bufToBytes(key);

    let k = keyBytes;
    if (k.length > blockSize) {
        k = bufToBytes(sha512(k));
    }
    if (k.length < blockSize) {
        const padded = new Uint8Array(blockSize);
        padded.set(k);
        k = padded;
    }

    const oKeyPad = new Uint8Array(blockSize);
    const iKeyPad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        oKeyPad[i] = k[i] ^ 0x5c;
        iKeyPad[i] = k[i] ^ 0x36;
    }

    const innerHash = sha512(concatBytes(iKeyPad, bufToBytes(data)));
    return sha512(concatBytes(oKeyPad, innerHash));
}

// ─── PBKDF2-HMAC-SHA512 ─────────────────────────────────────────

function pbkdf2HmacSha512(password, salt, iterations, keyLen) {
    const pw = bufToBytes(password);
    const slt = bufToBytes(salt);
    const blockCount = Math.ceil(keyLen / 64); // 64 = SHA-512 output length
    const result = new Uint8Array(keyLen);
    let pos = 0;

    for (let block = 1; block <= blockCount; block++) {
        // U_1 = PRF(Password, Salt || INT_32_BE(i))
        const blockBytes = new Uint8Array(slt.length + 4);
        blockBytes.set(slt);
        blockBytes[slt.length] = (block >>> 24) & 0xff;
        blockBytes[slt.length + 1] = (block >>> 16) & 0xff;
        blockBytes[slt.length + 2] = (block >>> 8) & 0xff;
        blockBytes[slt.length + 3] = block & 0xff;

        let u = hmacSha512(pw, blockBytes);
        let t = new Uint8Array(u);

        for (let i = 1; i < iterations; i++) {
            u = hmacSha512(pw, u);
            for (let j = 0; j < u.length; j++) {
                t[j] ^= u[j];
            }
        }

        const bytesToCopy = Math.min(64, keyLen - pos);
        for (let i = 0; i < bytesToCopy; i++) {
            result[pos + i] = t[i];
        }
        pos += bytesToCopy;
    }

    return Buffer.from(result);
}

// ─── Determine Web Crypto availability ───────────────────────────
// self.crypto.subtle is undefined in HTTP (non-secure) contexts.
// We check at call sites, not at load time, to allow dynamic context changes.

function getSubtle() {
    if (typeof crypto !== 'undefined' && crypto.subtle) return crypto.subtle;
    if (typeof self !== 'undefined' && self.crypto && self.crypto.subtle) return self.crypto.subtle;
    return null;
}

// ─── Counter (original AES-CTR counter) ──────────────────────────

class Counter {
    constructor(initialValue) {
        this._counter = Buffer.from(initialValue);
    }
    increment() {
        for (let i = 15; i >= 0; i--) {
            if (this._counter[i] === 255) {
                this._counter[i] = 0;
            } else {
                this._counter[i]++;
                break;
            }
        }
    }
}
exports.Counter = Counter;

// ─── CTR mode (AES-CTR, same as original) ────────────────────────

class CTR {
    constructor(key, counter) {
        if (!(counter instanceof Counter)) {
            counter = new Counter(counter);
        }
        this._counter = counter;
        this._remainingCounter = undefined;
        this._remainingCounterIndex = 16;
        this._aes = new aes_1.default(getWords(key));
    }
    update(plainText) {
        return this.encrypt(plainText);
    }
    encrypt(plainText) {
        const encrypted = Buffer.from(plainText);
        for (let i = 0; i < encrypted.length; i++) {
            if (this._remainingCounterIndex === 16) {
                this._remainingCounter = Buffer.from(i2ab(this._aes.encrypt(ab2i(this._counter._counter))));
                this._remainingCounterIndex = 0;
                this._counter.increment();
            }
            if (this._remainingCounter) {
                encrypted[i] ^= this._remainingCounter[this._remainingCounterIndex++];
            }
        }
        return encrypted;
    }
}
exports.CTR = CTR;

function createDecipheriv(algorithm, key, iv) {
    if (algorithm.includes("ECB")) {
        throw new Error("Not supported");
    } else {
        return new CTR(key, iv);
    }
}

function createCipheriv(algorithm, key, iv) {
    if (algorithm.includes("ECB")) {
        throw new Error("Not supported");
    } else {
        return new CTR(key, iv);
    }
}

function randomBytes(count) {
    const bytes = new Uint8Array(count);
    crypto.getRandomValues(bytes);
    return bytes;
}

// ─── Hash class with crypto.subtle fallback ──────────────────────

class Hash {
    constructor(algorithm) {
        this.algorithm = algorithm;
    }
    update(data) {
        this.data = new Uint8Array(data);
    }
    async digest() {
        if (this.data) {
            const subtle = getSubtle();

            if (this.algorithm === "sha1") {
                if (subtle && subtle.digest) {
                    return Buffer.from(await subtle.digest("SHA-1", this.data));
                }
                // Pure-JS fallback
                return sha1(this.data);
            } else if (this.algorithm === "sha256") {
                if (subtle && subtle.digest) {
                    return Buffer.from(await subtle.digest("SHA-256", this.data));
                }
                // Pure-JS fallback
                return sha256(this.data);
            } else if (this.algorithm === "sha512") {
                if (subtle && subtle.digest) {
                    return Buffer.from(await subtle.digest("SHA-512", this.data));
                }
                // Pure-JS fallback
                return sha512(this.data);
            }
        }
        return Buffer.alloc(0);
    }
}
exports.Hash = Hash;

// ─── pbkdf2Sync with crypto.subtle fallback ─────────────────────

async function pbkdf2Sync(password, salt, iterations, ...args) {
    const subtle = getSubtle();

    if (subtle && subtle.importKey && subtle.deriveBits) {
        try {
            const passwordKey = await subtle.importKey("raw", password, { name: "PBKDF2" }, false, ["deriveBits"]);
            return Buffer.from(await subtle.deriveBits({
                name: "PBKDF2",
                hash: "SHA-512",
                salt,
                iterations,
            }, passwordKey, 512));
        } catch (e) {
            // Fall through to pure-JS on any crypto error
        }
    }

    // Pure-JS PBKDF2-HMAC-SHA512 fallback
    return pbkdf2HmacSha512(password, salt, iterations, 64);
}

function createHash(algorithm) {
    return new Hash(algorithm);
}
