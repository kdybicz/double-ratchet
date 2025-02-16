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

export const GENERATE_DH = (): KeyPairSyncResult<string, string> => {
	return generateKeyPairSync("x25519", {
		publicKeyEncoding: {
			type: "spki",
			format: "pem",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "pem",
		},
	});
};

export const DH = (
	dh_pair: KeyPairSyncResult<string, string>,
	dh_pub: string,
): Buffer => {
	return diffieHellman({
		publicKey: createPublicKey(dh_pub),
		privateKey: createPrivateKey(dh_pair.privateKey),
	});
};

export const KDF_RK = (rk: Buffer<ArrayBufferLike>, dh_out: Buffer): [Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>] => {
	if (rk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${rk?.byteLength}`)
	}

	const kdf = hkdfSync("sha512", dh_out, rk, "app-specific-secret-key", 64);

	const rootKey = kdf.slice(0, 32);
	const chainKey = kdf.slice(32, 64);

	return [Buffer.from(rootKey), Buffer.from(chainKey)];
};

export const KDF_CK = (ck: Buffer<ArrayBufferLike>): [Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>] => {
	if (ck?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${ck?.byteLength}`)
	}

	const messageKey = createHmac("sha512", ck)
		.update(Buffer.from([0x01]))
		.digest().subarray(0, 32);
		// .digest("hex");
	const chainKey = createHmac("sha512", ck)
		.update(Buffer.from([0x02]))
		.digest().subarray(0, 32);
		// .digest("hex");

	return [messageKey, chainKey];
};

export const ENCRYPT = (
	mk: Buffer<ArrayBufferLike>,
	plaintext: string,
	associated_data: string,
): string => {
	if (mk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${mk?.byteLength}`)
	}

	const hashOutputLength = 80;
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const hkdf_out = hkdfSync(
		"sha512",
		mk,
		salt,
		"app-specific-encryption-key",
		hashOutputLength,
	);

	const encryptionKey = hkdf_out.slice(0, 32);
	const authenticationKey = hkdf_out.slice(32, 64);
	const iv = hkdf_out.slice(64);

	const cipher = createCipheriv(
		"aes-256-cbc",
		Buffer.from(encryptionKey),
		Buffer.from(iv),
	);

	// encrypt
	let ciphertext = cipher.update(plaintext, "utf-8", "hex");
	ciphertext += cipher.final("hex");

	// sign
	const message = `${associated_data}:${ciphertext}`;
	const signature = createHmac("sha512", Buffer.from(authenticationKey))
		.update(message)
		.digest("hex");

	return `${message}:${signature}`;
};

export const DECRYPT = (
	mk: Buffer<ArrayBufferLike>,
	encrypted_message: string,
): [string, string] => {
	if (mk?.byteLength !== 32) {
		throw new Error(`Invalid key size: ${mk?.byteLength}`)
	}

	const hashOutputLength = 80;
	const salt = Buffer.alloc(hashOutputLength, 0x00);
	const hkdf_out = hkdfSync(
		"sha512",
		mk,
		salt,
		"app-specific-encryption-key",
		hashOutputLength,
	);

	const decryptionKey = hkdf_out.slice(0, 32);
	const authenticationKey = hkdf_out.slice(32, 64);
	const iv = hkdf_out.slice(64);

	const cipher = createDecipheriv(
		"aes-256-cbc",
		Buffer.from(decryptionKey),
		Buffer.from(iv),
	);

	// prepare data
	const [associated_data, ciphertext, signature] = encrypted_message.split(":");

	// decrypt
	let plaintext = cipher.update(ciphertext, "hex", "utf-8");
	plaintext += cipher.final("utf-8");

	// sign
	const message = `${associated_data}:${ciphertext}`;
	const new_signature = createHmac("sha512", Buffer.from(authenticationKey))
		.update(message)
		.digest("hex");

	if (signature !== new_signature) {
		throw new Error("Invalid signature!");
	}

	return [plaintext, associated_data];
};
