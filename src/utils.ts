import {
	type KeyPairSyncResult,
	createCipheriv,
	createDecipheriv,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	hkdfSync,
} from "node:crypto";

/**
 * Returns a new Diffie-Hellman key pair.
 *
 * @returns
 */
export const GENERATE_DH = (): KeyPairSyncResult<Buffer, Buffer> => {
	return generateKeyPairSync("x25519", {
		publicKeyEncoding: {
			type: "spki",
			format: "der",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "der",
		},
	});
};

/**
 * Returns the output from the Diffie-Hellman calculation between the private
 * key from the DH key pair keyPair and the DH public key publicKey. If the DH
 * function rejects invalid public keys, then this function may raise an
 * exception which terminates processing.
 *
 * @param keyPair is a Diffie-Hellman key pair
 * @param publicKey is a hex representation of a Diffie-Hellman public key
 * @returns
 */
export const DH = (
	keyPair: KeyPairSyncResult<Buffer, Buffer>,
	publicKey: string,
): Buffer => {
	return diffieHellman({
		publicKey: createPublicKey({
			key: publicKey,
			format: "der",
			type: "spki",
			encoding: "hex",
		}),
		privateKey: createPrivateKey({
			key: keyPair.privateKey,
			format: "der",
			type: "pkcs8",
			encoding: "hex",
		}),
	});
};

/**
 * Returns a pair (32-byte root key, 32-byte chain key) as the output of
 * applying a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output
 * dhOut.
 *
 * @param rk is a 32-byte root key
 * @param dhOut
 * @returns
 */
export const KDF_RK = (
	rk: Buffer<ArrayBufferLike>,
	dhOut: Buffer,
): [Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>] => {
	if (rk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${rk?.byteLength}`);
	}

	const kdf = hkdfSync("sha512", dhOut, rk, "app-specific-secret-key", 64);

	const rootKey = kdf.slice(0, 32);
	const chainKey = kdf.slice(32);

	return [Buffer.from(rootKey), Buffer.from(chainKey)];
};

/**
 * Returns a pair (32-byte chain key, 32-byte message key) as the output of
 * applying a KDF keyed by a 32-byte chain key ck to some constant.
 *
 * @param ck is a 32-byte chain key
 * @returns
 */
export const KDF_CK = (
	ck: Buffer<ArrayBufferLike>,
): [Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>] => {
	if (ck?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${ck?.byteLength}`);
	}

	const messageKey = createHmac("sha512", ck)
		.update(Buffer.from([0x01]))
		.digest()
		.subarray(0, 32);
	// .digest("hex");
	const chainKey = createHmac("sha512", ck)
		.update(Buffer.from([0x02]))
		.digest()
		.subarray(0, 32);
	// .digest("hex");

	return [messageKey, chainKey];
};

/**
 * Returns an AEAD encryption of plaintext with message key mk. The
 * ad is authenticated but is not included in the ciphertext.
 * Because each message key is only used once, the AEAD nonce may handled in
 * several ways: fixed to a constant; derived from mk alongside an independent
 * AEAD encryption key; derived as an additional output from KDF_CK(); or
 * chosen randomly and transmitted.
 *
 * @param mk is a 32-byte message key
 * @param plaintext
 * @param ad is for associated data
 * @returns
 */
export const ENCRYPT = (
	mk: Buffer<ArrayBufferLike>,
	plaintext: string,
	ad: string,
): string => {
	if (mk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${mk?.byteLength}`);
	}

	const hashOutputLength = 80;
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const kdf = hkdfSync(
		"sha512",
		mk,
		salt,
		"app-specific-encryption-key",
		hashOutputLength,
	);

	const encryptionKey = kdf.slice(0, 32);
	const authenticationKey = kdf.slice(32, 64);
	const iv = kdf.slice(64);

	const cipher = createCipheriv(
		"aes-256-cbc",
		Buffer.from(encryptionKey),
		Buffer.from(iv),
	);

	// encrypt
	let ciphertext = cipher.update(plaintext, "utf-8", "hex");
	ciphertext += cipher.final("hex");

	// sign
	const signature = createHmac("sha512", Buffer.from(authenticationKey))
		.update(`${ad}${plaintext}`)
		.digest("hex");

	return `${ciphertext}${signature}`;
};

/**
 * Returns the AEAD decryption of ciphertext with message key mk. If
 * authentication fails, an exception will be raised that terminates
 * processing.
 *
 * @param mk is a 32-byte message key
 * @param message is the ciphertext with a signature appended to it
 * @param ad is for associated data
 * @returns
 */
export const DECRYPT = (
	mk: Buffer<ArrayBufferLike>,
	message: string,
	ad: string,
): string => {
	if (mk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${mk?.byteLength}`);
	}

	const hashOutputLength = 80;
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const kdf = hkdfSync(
		"sha512",
		mk,
		salt,
		"app-specific-encryption-key",
		hashOutputLength,
	);

	const decryptionKey = kdf.slice(0, 32);
	const authenticationKey = kdf.slice(32, 64);
	const iv = kdf.slice(64);

	const cipher = createDecipheriv(
		"aes-256-cbc",
		Buffer.from(decryptionKey),
		Buffer.from(iv),
	);

	// prepare data
	const ciphertext = message.substring(0, message.length - 128);
	const receivedSignature = message.substring(message.length - 128);

	// decrypt
	let plaintext = cipher.update(ciphertext, "hex", "utf-8");
	plaintext += cipher.final("utf-8");

	// sign
	const currentSignature = createHmac("sha512", Buffer.from(authenticationKey))
		.update(`${ad}${plaintext}`)
		.digest("hex");

	if (receivedSignature !== currentSignature) {
		throw new Error("Invalid signature!");
	}

	return plaintext;
};

export type Header = {
	dh: string;
	pn: number;
	n: number;
};

/**
 * Creates a new message header containing the DH ratchet public key from the
 * key pair in keyPair, the previous chain length pn, and the message number
 * n. The returned header object contains ratchet public key dh and integers
 * pn and n.
 *
 * @param keyPair is a Diffie-Hellman key pair
 * @param previousChainLength
 * @param messageNumber
 * @returns
 */
export const HEADER = (
	keyPair: KeyPairSyncResult<Buffer, Buffer>,
	previousChainLength: number,
	messageNumber: number,
): Header => {
	return {
		dh: keyPair.publicKey.toString("hex"),
		pn: previousChainLength,
		n: messageNumber,
	};
};

/**
 * Encodes a message header into a parseable byte sequence, prepends the ad
 * byte sequence, and returns the result. If ad is not guaranteed to be a
 * parseable byte sequence, a length value should be prepended to the output to
 * ensure that the output is parseable as a unique pair (ad, header).
 *
 * @param ad is for associated data
 * @param header
 * @returns
 */
export const CONCAT = (ad: Buffer, header: Header | string): string => {
	let headerString: string;
	if (typeof header === "string") {
		headerString = header;
	} else {
		headerString = JSON.stringify(header);
	}
	const associatedDataString = Buffer.from(ad).toString("hex");
	return `${associatedDataString}${headerString}`;
};

// specifies the maximum number of message keys that can be skipped in a single
// chain. It should be set high enough to tolerate routine lost or delayed
// messages, but low enough that a malicious sender can't trigger excessive
// recipient computation.
export const MAX_SKIP = 32;

/**
 * Returns the AEAD encryption of header with header key hk. Because the
 * same hk will be used repeatedly, the AEAD nonce must either be a stateful
 * non-repeating value, or must be a random non-repeating value chosen with at
 * least 128 bits of entropy.
 *
 * @param hk is a 32-byte header key
 * @param header
 */
export const HENCRYPT = (hk: Buffer<ArrayBufferLike>, header: Header) => {
	if (hk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${hk?.byteLength}`);
	}

	const hashOutputLength = 48;
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const kdf = hkdfSync(
		"sha512",
		hk,
		salt,
		"app-specific-header-encryption-key",
		hashOutputLength,
	);

	const encryptionKey = kdf.slice(0, 32);
	const iv = kdf.slice(32);

	const cipher = createCipheriv(
		"aes-256-cbc",
		Buffer.from(encryptionKey),
		Buffer.from(iv),
	);

	const plaintext = JSON.stringify(header);

	// encrypt
	let ciphertext = cipher.update(plaintext, "utf-8", "hex");
	ciphertext += cipher.final("hex");

	return ciphertext;
};

/**
 * Returns the authenticated decryption of ciphertext with header key hk. If
 * authentication fails, or if the header key hk is empty (None), returns None.
 *
 * @param hk is a 32-byte header key
 * @param ciphertext
 */
export const HDECRYPT = (
	hk: Buffer<ArrayBufferLike> | null,
	ciphertext: string,
): Header | null => {
	if (hk?.byteLength !== 32) {
		return null;
	}

	const hashOutputLength = 48;
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const kdf = hkdfSync(
		"sha512",
		hk,
		salt,
		"app-specific-header-encryption-key",
		hashOutputLength,
	);

	const decryptionKey = kdf.slice(0, 32);
	const iv = kdf.slice(32);

	const cipher = createDecipheriv(
		"aes-256-cbc",
		Buffer.from(decryptionKey),
		Buffer.from(iv),
	);

	// decrypt
	let plaintext = cipher.update(ciphertext, "hex", "utf-8");
	plaintext += cipher.final("utf-8");

	return JSON.parse(plaintext);
};

/**
 * Returns a new root key, chain key, and next header key as the output of
 * applying a KDF keyed by root key rk to a Diffie-Hellman output dhOut.
 *
 * @param rk is a 32-byte root key
 * @param dhOut
 * @returns
 */
export const KDF_RK_HE = (
	rk: Buffer<ArrayBufferLike>,
	dhOut: Buffer,
): [
	Buffer<ArrayBufferLike>,
	Buffer<ArrayBufferLike>,
	Buffer<ArrayBufferLike>,
] => {
	if (rk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${rk?.byteLength}`);
	}

	const kdf = hkdfSync("sha512", dhOut, rk, "app-specific-secret-key", 96);
	const kdfBuff = Buffer.from(kdf);

	const rootKey = kdfBuff.subarray(0, 32);
	const chainKey = kdfBuff.subarray(32, 64);
	const headerKey = kdfBuff.subarray(64, 96);

	return [rootKey, chainKey, headerKey];
};
