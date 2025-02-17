import { DoubleRatchet } from "../src";
import { GENERATE_DH, MAX_SKIP } from "../src/utils";

describe("double ratchet", () => {
	const keyPair = GENERATE_DH();
	const rootKey = Buffer.from("some random key some random key!");

	test("Initialize with recipients public key, able to send a message", () => {
		// when
		const ratchet = DoubleRatchet.fromPublicKey(
			rootKey,
			keyPair.publicKey.toString("hex"),
		);
		const [header, message] = ratchet.RatchetEncrypt(
			"plain text message",
			Buffer.from(""),
		);
		// then
		expect(header.dh).not.toEqual(keyPair.publicKey);
		expect(header.pn).toEqual(0);
		expect(header.n).toEqual(0);
		// and
		expect(message.length).toBeGreaterThan(0);
		expect(typeof message).toBe("string");
	});

	test("Initialize with sender key pair, unable to send a message ", () => {
		// when
		const ratchet = DoubleRatchet.fromKeyPair(rootKey, keyPair);
		// then
		expect(() =>
			ratchet.RatchetEncrypt("plain text message", Buffer.from("")),
		).toThrow("Chain Keys for sending not initialized!");
	});

	describe("Alice and Bob", () => {
		const ad = Buffer.from("random associated data");

		test("Send a message back and forth", () => {
			// given
			const bob = DoubleRatchet.fromKeyPair(rootKey, keyPair);
			// and
			const alice = DoubleRatchet.fromPublicKey(
				rootKey,
				keyPair.publicKey.toString("hex"),
			);

			// when
			const [headerA1, messageA1] = alice.RatchetEncrypt("Hi Bob!", ad);
			// then
			expect(bob.RatchetDecrypt(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			const [headerB1, messageB1] = bob.RatchetEncrypt("Hi Alice!", ad);
			// then
			expect(alice.RatchetDecrypt(headerB1, messageB1, ad)).toEqual(
				"Hi Alice!",
			);
		});

		test("Skip a single message", () => {
			// given
			const bob = DoubleRatchet.fromKeyPair(rootKey, keyPair);
			// and
			const alice = DoubleRatchet.fromPublicKey(
				rootKey,
				keyPair.publicKey.toString("hex"),
			);

			// when
			const [headerA1, messageA1] = alice.RatchetEncrypt("Hi Bob!", ad);
			const [headerA2, messageA2] = alice.RatchetEncrypt("Hi Bob 2!", ad);
			// then
			expect(bob.RatchetDecrypt(headerA2, messageA2, ad)).toEqual("Hi Bob 2!");
			expect(bob.RatchetDecrypt(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			const [headerB1, messageB1] = bob.RatchetEncrypt("Hi Alice!", ad);
			const [headerB2, messageB2] = bob.RatchetEncrypt("Hi Alice 2!", ad);
			// then
			expect(alice.RatchetDecrypt(headerB2, messageB2, ad)).toEqual(
				"Hi Alice 2!",
			);
			expect(alice.RatchetDecrypt(headerB1, messageB1, ad)).toEqual(
				"Hi Alice!",
			);
		});

		test("Skip a too many messages", () => {
			// given
			const bob = DoubleRatchet.fromKeyPair(rootKey, keyPair);
			// and
			const alice = DoubleRatchet.fromPublicKey(
				rootKey,
				keyPair.publicKey.toString("hex"),
			);
			for (let i = 0; i <= MAX_SKIP; i++) {
				alice.RatchetEncrypt("Hi Bob!", ad);
			}

			// when
			const [header, message] = alice.RatchetEncrypt("Hi Bob!", ad);
			// then
			expect(() => bob.RatchetDecrypt(header, message, ad)).toThrow(
				"Too many skipped messages!",
			);
		});
	});
});
