import { DoubleRatchet } from "../src/DoubleRatchet";
import { GENERATE_DH, MAX_SKIP } from "../src/utils";

describe("Double Ratchet", () => {
	const initiatorKeyPair = GENERATE_DH();
	const responderKeyPair = GENERATE_DH();

	const rootKey = Buffer.from("some random key some random key!");
	const ad = Buffer.from("random associated data");

	test("Initialize and send first message", () => {
		// when
		const ratchet = DoubleRatchet.fromInitiatorSide(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		const [header, message] = ratchet.RatchetEncrypt("plain text message", ad);
		// then
		expect(header.dh).not.toEqual(responderKeyPair.publicKey);
		expect(header.pn).toEqual(0);
		expect(header.n).toEqual(0);
		// and
		expect(message.length).toBeGreaterThan(0);
		expect(typeof message).toBe("string");
	});

	describe("Alice and Bob", () => {
		test("Send a message back and forth", () => {
			// given
			const alice = DoubleRatchet.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
			);
			// and
			const bob = DoubleRatchet.fromResponderSide(rootKey, responderKeyPair);

			// when
			let [headerA1, messageA1] = alice.RatchetEncrypt("Hi Bob!", ad);
			// then
			expect(bob.RatchetDecrypt(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			[headerA1, messageA1] = alice.RatchetEncrypt("Hi Bob!", ad);
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
			const alice = DoubleRatchet.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
			);
			// and
			const bob = DoubleRatchet.fromResponderSide(rootKey, responderKeyPair);

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

		test("Skip multiple messages at random", () => {
			// given
			const alice = DoubleRatchet.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
			);
			// and
			const bob = DoubleRatchet.fromResponderSide(rootKey, responderKeyPair);

			// when
			const [headerA1, messageA1] = alice.RatchetEncrypt("Hi Bob!", ad);
			const [headerA2, messageA2] = alice.RatchetEncrypt("Hi Bob 2!", ad);
			const [headerA3, messageA3] = alice.RatchetEncrypt("Hi Bob 3!", ad);
			const [headerA4, messageA4] = alice.RatchetEncrypt("Hi Bob 4!", ad);
			const [headerA5, messageA5] = alice.RatchetEncrypt("Hi Bob 5!", ad);
			// then
			expect(bob.RatchetDecrypt(headerA2, messageA2, ad)).toEqual("Hi Bob 2!");
			expect(bob.RatchetDecrypt(headerA5, messageA5, ad)).toEqual("Hi Bob 5!");
			expect(bob.RatchetDecrypt(headerA4, messageA4, ad)).toEqual("Hi Bob 4!");
			expect(bob.RatchetDecrypt(headerA3, messageA3, ad)).toEqual("Hi Bob 3!");
			expect(bob.RatchetDecrypt(headerA1, messageA1, ad)).toEqual("Hi Bob!");

			// when
			const [headerB1, messageB1] = bob.RatchetEncrypt("Hi Alice!", ad);
			const [headerB2, messageB2] = bob.RatchetEncrypt("Hi Alice 2!", ad);
			const [headerB3, messageB3] = bob.RatchetEncrypt("Hi Alice 3!", ad);
			const [headerB4, messageB4] = bob.RatchetEncrypt("Hi Alice 4!", ad);
			const [headerB5, messageB5] = bob.RatchetEncrypt("Hi Alice 5!", ad);
			// then
			expect(alice.RatchetDecrypt(headerB2, messageB2, ad)).toEqual(
				"Hi Alice 2!",
			);
			expect(alice.RatchetDecrypt(headerB5, messageB5, ad)).toEqual(
				"Hi Alice 5!",
			);
			expect(alice.RatchetDecrypt(headerB4, messageB4, ad)).toEqual(
				"Hi Alice 4!",
			);
			expect(alice.RatchetDecrypt(headerB3, messageB3, ad)).toEqual(
				"Hi Alice 3!",
			);
			expect(alice.RatchetDecrypt(headerB1, messageB1, ad)).toEqual(
				"Hi Alice!",
			);
		});

		test("Skip a too many messages", () => {
			// given
			const alice = DoubleRatchet.fromInitiatorSide(
				rootKey,
				initiatorKeyPair,
				responderKeyPair.publicKey.toString("hex"),
			);
			for (let i = 0; i <= MAX_SKIP; i++) {
				alice.RatchetEncrypt("Hi Bob!", ad);
			}
			// and
			const bob = DoubleRatchet.fromResponderSide(rootKey, responderKeyPair);

			// when
			const [header, message] = alice.RatchetEncrypt("Hi Bob!", ad);
			// then
			expect(() => bob.RatchetDecrypt(header, message, ad)).toThrow(
				"Too many skipped messages!",
			);
		});
	});
});
