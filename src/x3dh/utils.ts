import {
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	hkdfSync,
} from "node:crypto";

/**
 * Returns a byte sequence which is the shared secret output from an Elliptic
 * Curve Diffie-Hellman function involving the key pairs represented by public
 * keys PK1 and PK2. The Elliptic Curve Diffie-Hellman function will be either
 * the X25519 or X448 function from [1], depending on the curve parameter.
 *
 * @param PK1 is a byte representation of a Diffie-Hellman private key
 * @param PK2 is a byte representation of a Diffie-Hellman public key
 * @returns
 */
export const DH = (
	PK1: Buffer<ArrayBufferLike>,
	PK2: Buffer<ArrayBufferLike>,
): Buffer<ArrayBufferLike> => {
	return diffieHellman({
		publicKey: createPublicKey({
			key: PK2,
			format: "der",
			type: "spki",
		}),
		privateKey: createPrivateKey({
			key: PK1,
			format: "der",
			type: "pkcs8",
		}),
	});
};

/**
 * Represents a byte sequence that is an XEdDSA signature on the byte sequence
 * M and verifies with public key PK, and which was created by signing M with
 * PK's corresponding private key.
 *
 * @param PK
 * @param M
 */
export const Sig = (
	PK: Buffer<ArrayBufferLike>,
	M: Buffer<ArrayBufferLike>,
): Buffer<ArrayBufferLike> => {
	return Buffer.from("here is signature");
};

export const SigVer = (
	PK: Buffer<ArrayBufferLike>,
	S: Buffer<ArrayBufferLike>,
): boolean => {
	return Buffer.compare(S, Buffer.from("here is signature")) === 0;
};

/**
 * Returns 32 bytes of output from the HKDF algorithm [3] with inputs:
 * - HKDF input key material = F || KM, where KM is an input byte sequence
 *    containing secret key material, and F is a byte sequence containing
 *    32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448.
 *    F is used for cryptographic domain separation with XEdDSA [2].
 * - HKDF salt = A zero-filled byte sequence with length equal to the hash
 *    output length.
 * - HKDF info = The info parameter from Section 2.1.
 *
 * @param KM
 */
export const KDF = (KM: Buffer<ArrayBufferLike>): Buffer => {
	const hashOutputLength = 32;
	const F = Buffer.alloc(hashOutputLength, 0xff);
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const info = "My super secret app";

	const kdf = hkdfSync(
		"sha512",
		Buffer.concat([F, KM]),
		salt,
		info,
		hashOutputLength,
	);

	return Buffer.from(kdf);
};

/**
 * Function encode an X25519 or X448 public key PK into a byte sequence. The
 * recommended encoding consists of some single-byte constant to represent the
 * type of curve, followed by little-endian encoding of the u-coordinate.
 *
 * More details: https://crypto.stackexchange.com/questions/47409/what-is-a-u-coordinate-within-elliptic-curve-diffie-hellman-using-the-montgomery?rq=1
 *
 * Constant:
 * - 0x00 for X25519 public key
 * - 0x01 for X448 public key
 *
 * @param PK is for the public key
 */
export const Encode = (PK: Buffer<ArrayBufferLike>) => {
	return Buffer.concat([Buffer.from([0x00]), PK]);
};
