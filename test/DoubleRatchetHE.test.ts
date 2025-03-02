import { DoubleRatchetHE } from "../src/DoubleRatchetHE";
import { GENERATE_DH, MAX_SKIP } from "../src/utils";

describe("Double Ratchet with header encryption", () => {
	const initiatorKeyPair = GENERATE_DH();
	const responderKeyPair = GENERATE_DH();

	const rootKey = Buffer.from("some random key some random key!");
	const ad = Buffer.from("random associated data");

	const shared_hka = Buffer.from("random some key random some key!");
	const shared_nhkb = Buffer.from("key some random key some random!");

	test("Initialize with recipients public key, able to send a message", () => {
		// when
		const ratchet = DoubleRatchetHE.fromInitiatorSide(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
			shared_hka,
			shared_nhkb,
		);
		const [header, message] = ratchet.RatchetEncryptHE(
			"plain text message",
			Buffer.from(""),
		);
		// then
		expect(header.length).toBeGreaterThan(0);
		expect(typeof header).toBe("string");
		// and
		expect(message.length).toBeGreaterThan(0);
		expect(typeof message).toBe("string");
	});

	test("Initialize with sender key pair, unable to send a message ", () => {
		// when
		const ratchet = DoubleRatchetHE.fromResponderSide(
			rootKey,
			responderKeyPair,
			shared_hka,
			shared_nhkb,
		);
		// then
		expect(() =>
			ratchet.RatchetEncryptHE("plain text message", Buffer.from("")),
		).toThrow("Chain Key for sending not initialized!");
	});

	describe("Alice and Bob", () => {
		test("Send a message back and forth", () => {
			// given
			const alice = DoubleRatchetHE.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
				shared_hka,
				shared_nhkb,
			);
			// and
			const bob = DoubleRatchetHE.fromResponderSide(
				rootKey,
				responderKeyPair,
				shared_hka,
				shared_nhkb,
			);

			// when
			const [headerA1, messageA1] = alice.RatchetEncryptHE("Hi Bob!", ad);
			// then
			expect(bob.RatchetDecryptHE(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			const [headerB1, messageB1] = bob.RatchetEncryptHE("Hi Alice!", ad);
			// then
			expect(alice.RatchetDecryptHE(headerB1, messageB1, ad)).toEqual(
				"Hi Alice!",
			);
		});

		test("Skip a single message", () => {
			// given
			const alice = DoubleRatchetHE.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
				shared_hka,
				shared_nhkb,
			);
			// and
			const bob = DoubleRatchetHE.fromResponderSide(
				rootKey,
				responderKeyPair,
				shared_hka,
				shared_nhkb,
			);

			// when
			const [headerA1, messageA1] = alice.RatchetEncryptHE("Hi Bob!", ad);
			const [headerA2, messageA2] = alice.RatchetEncryptHE("Hi Bob 2!", ad);
			// then
			expect(bob.RatchetDecryptHE(headerA2, messageA2, ad)).toEqual(
				"Hi Bob 2!",
			);
			expect(bob.RatchetDecryptHE(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			const [headerB1, messageB1] = bob.RatchetEncryptHE("Hi Alice!", ad);
			const [headerB2, messageB2] = bob.RatchetEncryptHE("Hi Alice 2!", ad);
			// then
			expect(alice.RatchetDecryptHE(headerB2, messageB2, ad)).toEqual(
				"Hi Alice 2!",
			);
			expect(alice.RatchetDecryptHE(headerB1, messageB1, ad)).toEqual(
				"Hi Alice!",
			);
		});

		test("Skip multiple messages at random", () => {
			// given
			const alice = DoubleRatchetHE.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
				shared_hka,
				shared_nhkb,
			);
			// and
			const bob = DoubleRatchetHE.fromResponderSide(
				rootKey,
				responderKeyPair,
				shared_hka,
				shared_nhkb,
			);

			// when
			const [headerA1, messageA1] = alice.RatchetEncryptHE("Hi Bob!", ad);
			const [headerA2, messageA2] = alice.RatchetEncryptHE("Hi Bob 2!", ad);
			const [headerA3, messageA3] = alice.RatchetEncryptHE("Hi Bob 3!", ad);
			const [headerA4, messageA4] = alice.RatchetEncryptHE("Hi Bob 4!", ad);
			const [headerA5, messageA5] = alice.RatchetEncryptHE("Hi Bob 5!", ad);
			// then
			expect(bob.RatchetDecryptHE(headerA2, messageA2, ad)).toEqual(
				"Hi Bob 2!",
			);
			expect(bob.RatchetDecryptHE(headerA5, messageA5, ad)).toEqual(
				"Hi Bob 5!",
			);
			expect(bob.RatchetDecryptHE(headerA4, messageA4, ad)).toEqual(
				"Hi Bob 4!",
			);
			expect(bob.RatchetDecryptHE(headerA3, messageA3, ad)).toEqual(
				"Hi Bob 3!",
			);
			expect(bob.RatchetDecryptHE(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			const [headerB1, messageB1] = bob.RatchetEncryptHE("Hi Alice!", ad);
			const [headerB2, messageB2] = bob.RatchetEncryptHE("Hi Alice 2!", ad);
			const [headerB3, messageB3] = bob.RatchetEncryptHE("Hi Alice 3!", ad);
			const [headerB4, messageB4] = bob.RatchetEncryptHE("Hi Alice 4!", ad);
			const [headerB5, messageB5] = bob.RatchetEncryptHE("Hi Alice 5!", ad);
			// then
			expect(alice.RatchetDecryptHE(headerB2, messageB2, ad)).toEqual(
				"Hi Alice 2!",
			);
			expect(alice.RatchetDecryptHE(headerB5, messageB5, ad)).toEqual(
				"Hi Alice 5!",
			);
			expect(alice.RatchetDecryptHE(headerB4, messageB4, ad)).toEqual(
				"Hi Alice 4!",
			);
			expect(alice.RatchetDecryptHE(headerB3, messageB3, ad)).toEqual(
				"Hi Alice 3!",
			);
			expect(alice.RatchetDecryptHE(headerB1, messageB1, ad)).toEqual(
				"Hi Alice!",
			);
		});

		test("Skip a too many messages", () => {
			// given
			const alice = DoubleRatchetHE.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
				shared_hka,
				shared_nhkb,
			);
			for (let i = 0; i <= MAX_SKIP; i++) {
				alice.RatchetEncryptHE("Hi Bob!", ad);
			}
			// and
			const bob = DoubleRatchetHE.fromResponderSide(
				rootKey,
				responderKeyPair,
				shared_hka,
				shared_nhkb,
			);

			// when
			const [header, message] = alice.RatchetEncryptHE("Hi Bob!", ad);
			// then
			expect(() => bob.RatchetDecryptHE(header, message, ad)).toThrow(
				"Too many skipped messages!",
			);
		});
	});
});
