import { type KeyPairSyncResult, createHash } from "node:crypto";

const p: bigint = (1n << 255n) - 19n;
const q: bigint = (1n << 252n) + 27742317777372353535851937790883648493n;
const d: bigint = ((p - 121665n) * modInv(121666n, p)) % p;

function bytesToBigIntLE(buffer: Buffer): bigint {
	let res = 0n;
	for (let i = buffer.length - 1; i >= 0; i--) {
		res = (res << 8n) + BigInt(buffer[i]);
	}
	return res;
}

function bigIntToBufferLE(num: bigint, length: number): Buffer {
	const buf = Buffer.alloc(length);

	let localNum = num;
	for (let i = 0; i < length; i++) {
		buf[i] = Number(localNum & 0xffn);
		localNum >>= 8n;
	}

	return buf;
}

function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
	let result = 1n;
	let localBase = base;
	let localExp = exp;

	localBase %= mod;
	while (localExp > 0n) {
		if (localExp % 2n === 1n) {
			result = (result * localBase) % mod;
		}
		localExp /= 2n;
		localBase = (localBase * localBase) % mod;
	}
	return result;
}

function modInv(x: bigint, mod: bigint): bigint {
	return modExp(x, mod - 2n, mod);
}

function modSqrt(a: bigint, mod: bigint): bigint {
	const exp = (mod + 3n) >> 3n;
	let x = modExp(a, exp, mod);
	if ((x * x) % mod !== a % mod) {
		const factor = modExp(2n, (mod - 1n) >> 2n, mod);
		x = (x * factor) % mod;
	}
	return x;
}

/**
 * Computes SHA-512(prefix || X), where the prefix is 32 bytes of 0xFF
 * except that the first byte is (0xFF - i). The 64-byte hash is parsed
 * as a little-endian bigint.
 */
function hashi(i: number, X: Buffer): bigint {
	const prefix = Buffer.alloc(32, 0xff);
	prefix[0] = (0xff - i) & 0xff;
	const data = Buffer.concat([prefix, X]);
	const hashBuf = createHash("sha512").update(data).digest();

	let hashInt = 0n;
	for (let j = 0; j < hashBuf.length; j++) {
		hashInt += BigInt(hashBuf[j]) << (8n * BigInt(j));
	}

	return hashInt;
}

/**
 * Extracts the raw 32-byte key material from a DER-encoded PKCS#8 x25519 private key.
 * This heuristic looks for the pattern "0420" (tag 0x04 followed by length 0x20)
 * and returns the following 32 bytes.
 */
function extractRawX25519PrivateKey(privateKey: Buffer): Buffer {
	const hex = privateKey.toString("hex");
	const pattern = "0420";
	const index = hex.indexOf(pattern);
	if (index === -1) {
		throw new Error("Could not find pattern 0420 in DER key");
	}

	const offset = index / 2 + 2;
	const raw = privateKey.subarray(offset, offset + 32);
	if (raw.length !== 32) {
		throw new Error("Extracted key is not 32 bytes");
	}

	return raw;
}

/**
 * Extracts the raw 32-byte key from a DER-encoded SPKI x25519 public key.
 * Assumes the raw key is the last 32 bytes.
 */
function extractRawX25519PublicKey(publicKey: Buffer): Buffer {
	if (publicKey.length < 32) {
		throw new Error("DER public key too short");
	}
	return publicKey.subarray(publicKey.length - 32);
}

/**
 * EdwardsPoint class encapsulates curve point operations
 */
export class EdwardsPoint {
	// Twisted Edwards base point
	public static B = new EdwardsPoint(
		15112221349535400772501151409588531511454012693041857206046113283949847762202n,
		46316835694926478169428394003475163141307993866256225615783033603165251855960n,
	);

	public readonly x: bigint;
	public readonly y: bigint;

	constructor(x: bigint, y: bigint) {
		this.x = x;
		this.y = y;
	}

	public add(point: EdwardsPoint): EdwardsPoint {
		const x1 = this.x;
		const y1 = this.y;
		const x2 = point.x;
		const y2 = point.y;
		const numeratorX = (x1 * y2 + y1 * x2) % p;
		const denominatorX = (1n + d * x1 * x2 * y1 * y2) % p;
		const x3 = (numeratorX * modInv(denominatorX, p)) % p;
		const numeratorY = (y1 * y2 + x1 * x2) % p;
		const denominatorY = (1n - d * x1 * x2 * y1 * y2) % p;
		const y3 = (numeratorY * modInv(denominatorY, p)) % p;
		return new EdwardsPoint((x3 + p) % p, (y3 + p) % p);
	}

	public double(): EdwardsPoint {
		return this.add(this);
	}

	public clone(): EdwardsPoint {
		return new EdwardsPoint(this.x, this.y);
	}

	public scalarMultiply(scalar: bigint): EdwardsPoint {
		let R = EdwardsPoint.identity();
		let P = this.clone();
		let k = scalar;
		while (k > 0n) {
			if (k & 1n) {
				R = R.add(P);
			}
			P = P.double();
			k >>= 1n;
		}
		return R;
	}

	public compress(): Buffer {
		const buff = bigIntToBufferLE(this.y, 32);
		if (this.x & 1n) {
			buff[31] |= 0x80;
		} else {
			buff[31] &= 0x7f;
		}
		return buff;
	}

	public static decompress(compressed: Buffer): EdwardsPoint {
		if (compressed.length !== 32) {
			throw new Error("Compressed point must be 32 bytes");
		}

		const yBytes = Buffer.from(compressed);
		yBytes[31] &= 0x7f;
		const y = bytesToBigIntLE(yBytes);
		const sign = compressed[31] & 0x80 ? 1 : 0;
		const y2 = (y * y) % p;
		const numerator = (y2 - 1n + p) % p;
		const denominator = (1n + d * y2) % p;
		const x2 = (numerator * modInv(denominator, p)) % p;

		let x = modSqrt(x2, p);
		if ((x & 1n ? 1 : 0) !== sign) {
			x = (p - x) % p;
		}

		return new EdwardsPoint(x, y);
	}

	public static negate(point: EdwardsPoint): EdwardsPoint {
		return new EdwardsPoint((p - point.x) % p, point.y);
	}

	public static onCurve(point: EdwardsPoint): boolean {
		const x2 = (point.x * point.x) % p;
		const y2 = (point.y * point.y) % p;
		const lhs = (y2 - x2 + p) % p;
		const rhs = (1n + d * x2 * y2) % p;
		return lhs === rhs;
	}

	public static identity(): EdwardsPoint {
		return new EdwardsPoint(0n, 1n);
	}

	/**
	 * Computes y = (u - 1) / (u + 1) mod p.
	 */
	protected static uToY(u: bigint, p: bigint): bigint {
		const numerator = (u - 1n + p) % p;
		const denominator = (u + 1n) % p;
		return (numerator * modInv(denominator, p)) % p;
	}

	/**
	 * Converts a DER-encoded x25519 public key into a full EdwardsPoint.
	 * It extracts the raw key (last 32 bytes), converts it to bigint u (little-endian),
	 * reduces u modulo 2p, computes y = (u - 1)/(u + 1) mod p, and then recovers x
	 * from the curve equation (choosing the square root with even parity).
	 */
	public static fromMontgomery(publicKey: Buffer): EdwardsPoint {
		const raw = extractRawX25519PublicKey(publicKey);
		const u = bytesToBigIntLE(raw);
		const twoP = 2n * p;
		const umasked = ((u % twoP) + twoP) % twoP;
		const y = EdwardsPoint.uToY(umasked, p);
		const y2 = (y * y) % p;
		const numerator = (y2 - 1n + p) % p;
		const denominator = (1n + d * y2) % p;
		const x2 = (numerator * modInv(denominator, p)) % p;

		let x = modSqrt(x2, p);
		if (x & 1n) {
			x = (p - x) % p;
		}

		return new EdwardsPoint(x, y);
	}
}

/**
 * Given an x25519 private key in DER format, extracts the raw 32-byte seed k,
 * computes E = kB on Ed25519, and then:
 *   A = compress(E) with sign forced to 0 (i.e. A.y = E.y, A.s = 0)
 *   a = (-k mod q) if E.x is odd, else (k mod q)
 * Returns { A, a } where A and a are 32-byte Buffers.
 */
export function calculateKeyPair(
	privateKey: Buffer,
): KeyPairSyncResult<Buffer, Buffer> {
	const rawKey = extractRawX25519PrivateKey(privateKey);
	const kInt = bytesToBigIntLE(rawKey);

	// Compute E = kB. Use the EdwardsPoint scalarMultiply method.
	const E = EdwardsPoint.B.scalarMultiply(kInt);
	const E_s = (E.x & 1n) === 1n ? 1 : 0;
	const A = bigIntToBufferLE(E.y, 32);
	A[31] &= 0x7f; // Force sign bit to 0.

	const aInt = E_s === 1 ? ((-kInt % q) + q) % q : kInt % q;
	const a = bigIntToBufferLE(aInt, 32);

	return { publicKey: A, privateKey: a };
}

/**
 * Signs message M using the x25519 private key in DER format and a 64-byte random nonce Z.
 * Returns a 64-byte signature: 32-byte compressed R || 32-byte s.
 */
export function sign(privateKey: Buffer, M: Buffer, Z: Buffer): Buffer {
	if (Z.length !== 64) {
		throw new Error("Z must be 64 bytes");
	}

	const { publicKey: A, privateKey: a } = calculateKeyPair(privateKey);
	const aInt = bytesToBigIntLE(a);

	const r = hashi(1, Buffer.concat([a, M, Z])) % q;
	const R = EdwardsPoint.B.scalarMultiply(r).compress();
	const h = hashi(0, Buffer.concat([R, A, M])) % q;
	const s = (r + h * aInt) % q;

	return Buffer.concat([R, bigIntToBufferLE(s, 32)]);
}

/**
 * Verifies a 64-byte XEdDSA signature (R || s) for message M using the x25519 public key in DER format.
 * Returns true if valid, false otherwise.
 */
export function verify(publicKey: Buffer, M: Buffer, sig: Buffer): boolean {
	if (sig.length !== 64) {
		return false;
	}

	const R_comp = sig.subarray(0, 32);
	const sInt = bytesToBigIntLE(sig.subarray(32, 64));
	if (sInt >= 1n << 253n) {
		return false;
	}

	let R_point: EdwardsPoint;
	try {
		R_point = EdwardsPoint.decompress(R_comp);
	} catch {
		return false;
	}
	if (R_point.y >= 1n << 255n) {
		return false;
	}

	let uRaw: Buffer;
	try {
		uRaw = extractRawX25519PublicKey(publicKey);
	} catch {
		return false;
	}

	if (bytesToBigIntLE(uRaw) >= p) {
		return false;
	}

	// Convert Montgomery public key to Edwards point.
	const A_point = EdwardsPoint.fromMontgomery(publicKey);
	const A_comp = A_point.compress();

	if (!EdwardsPoint.onCurve(A_point)) {
		return false;
	}

	const h = hashi(0, Buffer.concat([R_comp, A_comp, M])) % q;
	const sB = EdwardsPoint.B.scalarMultiply(sInt);
	const hA = A_point.scalarMultiply(h);
	const Rcheck = sB.add(EdwardsPoint.negate(hA)).compress();

	return R_comp.equals(Rcheck);
}
