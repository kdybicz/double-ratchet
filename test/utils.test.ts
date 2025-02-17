import {
	CONCAT,
	DECRYPT,
	DH,
	ENCRYPT,
	GENERATE_DH,
	HEADER,
	KDF_CK,
	KDF_RK,
} from "../src/utils";

describe("utils", () => {
	test("Generate Diffie-Hellman key pair", () => {
		// given
		const pair = GENERATE_DH();

		// expect
		expect(typeof pair.publicKey).toBe("object");
		expect(typeof pair.privateKey).toBe("object");
	});

	test("Generate Alice and Bob Diffie-Hellman secrets that match", () => {
		// given
		const alice = GENERATE_DH();
		const bob = GENERATE_DH();

		// when
		const secret1 = DH(alice, bob.publicKey.toString("hex"));
		const secret2 = DH(bob, alice.publicKey.toString("hex"));

		expect(secret1.toString("hex")).toEqual(secret2.toString("hex"));
	});

	test("Derive new ratchet key and chain key", () => {
		// given
		const alice = GENERATE_DH();
		const bob = GENERATE_DH();
		// and
		const rootKey = Buffer.from("some random key some random key!");
		const secret = DH(alice, bob.publicKey.toString("hex"));

		// when
		const [rootKey1, chainKey1] = KDF_RK(rootKey, secret);
		// then
		expect(rootKey1.byteLength).toEqual(32);
		expect(chainKey1.byteLength).toEqual(32);

		// when
		const [rootKey2, chainKey2] = KDF_RK(rootKey, secret);
		// then
		expect(rootKey2).toEqual(rootKey1);
		expect(chainKey2).toEqual(chainKey1);

		// when
		const [rootKey3, chainKey3] = KDF_RK(rootKey2, secret);
		// then
		expect(rootKey3).not.toEqual(rootKey1);
		expect(chainKey3).not.toEqual(chainKey1);
	});

	test("Derive message key and new chain key", () => {
		// given
		const oldChainKey = Buffer.from("some random key some random key!");

		// when
		const [messageKey1, newChainKey1] = KDF_CK(oldChainKey);
		// then
		expect(messageKey1.byteLength).toEqual(32);
		expect(newChainKey1.byteLength).toEqual(32);

		// when
		const [messageKey2, newChainKey2] = KDF_CK(oldChainKey);
		// then
		expect(messageKey1).toEqual(messageKey2);
		expect(newChainKey1).toEqual(newChainKey2);

		// when
		const [messageKey3, chainKey3] = KDF_CK(newChainKey2);
		// then
		expect(messageKey2).not.toEqual(messageKey3);
		expect(newChainKey2).not.toEqual(chainKey3);
	});

	test("encrypt", () => {
		// given
		const masterKey = Buffer.from("some random key some random key!");
		const plaintext = "plain text";
		const associatedData = "some data";

		// when
		const encrypted = ENCRYPT(masterKey, plaintext, associatedData);
		// then
		expect(typeof encrypted).toBe("string");
		expect(encrypted).not.toEqual(plaintext);
	});

	test("decrypt", () => {
		// given
		const masterKey = Buffer.from("some random key some random key!");
		const plaintext = "plain text";
		const associatedData = "some data";
		// and
		const encrypted = ENCRYPT(masterKey, plaintext, associatedData);

		// when
		const decryptedText = DECRYPT(masterKey, encrypted, associatedData);
		// then
		expect(decryptedText).toEqual(plaintext);
	});

	test("header", () => {
		// given
		const pair = GENERATE_DH();

		// when
		const header = HEADER(pair, 4, 5);
		// then
		expect(header).toEqual({
			dh: pair.publicKey.toString("hex"),
			pn: 4,
			n: 5,
		});
	});

	test("concat", () => {
		// given
		const pair = GENERATE_DH();
		// and
		const header = HEADER(pair, 4, 5);
		// and
		const associatedData = Buffer.from("some random data");

		// when
		const headerWithAssociatedData = CONCAT(associatedData, header);
		// then
		expect(headerWithAssociatedData).toEqual(
			`${associatedData.toString("hex")}${JSON.stringify({
				dh: pair.publicKey.toString("hex"),
				pn: 4,
				n: 5,
			})}`,
		);
	});
});
