import { GENERATE_DH, MAX_SKIP } from "../../src/utils";
import {
	InitState,
	RatchetDecrypt,
	RatchetEncrypt,
} from "../../src/x3dh/ratchet";

describe("X3DH Double Ratchet", () => {
	const senderKeyPair = GENERATE_DH();
	const recipientKeyPair = GENERATE_DH();

	const rootKey = Buffer.from("some random key some random key!");
	const ad = Buffer.from("random associated data");

	test("Initialize state, send first message", () => {
		// given
		const state = InitState(
			rootKey,
			senderKeyPair,
			recipientKeyPair.publicKey.toString("hex"),
		);

		// when
		const [, header, message] = RatchetEncrypt(state, "plain text message", ad);
		// then
		expect(header.dh).not.toEqual(recipientKeyPair.publicKey);
		expect(header.pn).toEqual(0);
		expect(header.n).toEqual(0);
		// and
		expect(message.length).toBeGreaterThan(0);
		expect(typeof message).toBe("string");
	});

	describe("Alice and Bob", () => {
		test("Send a message back and forth", () => {
			// given
			const bobState0 = InitState(
				rootKey,
				recipientKeyPair,
				senderKeyPair.publicKey.toString("hex"),
			);
			// and
			const aliceState0 = InitState(
				rootKey,
				senderKeyPair,
				recipientKeyPair.publicKey.toString("hex"),
			);

			// when
			const [aliceState1, headerA1, messageA1] = RatchetEncrypt(
				aliceState0,
				"Hi Bob!",
				ad,
			);
			const [bobState1, messageB1] = RatchetDecrypt(
				bobState0,
				headerA1,
				messageA1,
				ad,
			);
			// then
			expect(messageB1).toEqual("Hi Bob!");

			// when
			const [aliceState2, headerA2, messageA2] = RatchetEncrypt(
				aliceState1,
				"Hi Bob!",
				ad,
			);
			const [bobState2, messageB2] = RatchetDecrypt(
				bobState1,
				headerA2,
				messageA2,
				ad,
			);
			// then
			expect(messageB2).toEqual("Hi Bob!");

			// when
			const [, headerB3, messageB3] = RatchetEncrypt(
				bobState2,
				"Hi Alice!",
				ad,
			);
			const [, messageA3] = RatchetDecrypt(
				aliceState2,
				headerB3,
				messageB3,
				ad,
			);
			// then
			expect(messageA3).toEqual("Hi Alice!");
		});

		test("Skip a single message", () => {
			// given
			const bobState0 = InitState(
				rootKey,
				recipientKeyPair,
				senderKeyPair.publicKey.toString("hex"),
			);
			// and
			const aliceState0 = InitState(
				rootKey,
				senderKeyPair,
				recipientKeyPair.publicKey.toString("hex"),
			);

			// when
			const [aliceState1, headerA1, messageA1] = RatchetEncrypt(
				aliceState0,
				"Hi Bob!",
				ad,
			);
			const [aliceState2, headerA2, messageA2] = RatchetEncrypt(
				aliceState1,
				"Hi Bob 2!",
				ad,
			);
			// and
			const [bobState1, messageB1] = RatchetDecrypt(
				bobState0,
				headerA2,
				messageA2,
				ad,
			);
			const [bobState2, messageB2] = RatchetDecrypt(
				bobState1,
				headerA1,
				messageA1,
				ad,
			);
			// then
			expect(messageB1).toEqual("Hi Bob 2!");
			expect(messageB2).toEqual("Hi Bob!");

			// when
			const [bobState3, headerB3, messageB3] = RatchetEncrypt(
				bobState2,
				"Hi Alice!",
				ad,
			);
			const [, headerB4, messageB4] = RatchetEncrypt(
				bobState3,
				"Hi Alice 2!",
				ad,
			);
			// and
			const [aliceState3, messageA3] = RatchetDecrypt(
				aliceState2,
				headerB4,
				messageB4,
				ad,
			);
			const [, messageA4] = RatchetDecrypt(
				aliceState3,
				headerB3,
				messageB3,
				ad,
			);
			// then
			expect(messageA3).toEqual("Hi Alice 2!");
			expect(messageA4).toEqual("Hi Alice!");
		});

		test("Skip multiple messages at random", () => {
			// given
			const bobState0 = InitState(
				rootKey,
				recipientKeyPair,
				senderKeyPair.publicKey.toString("hex"),
			);
			// and
			const aliceState0 = InitState(
				rootKey,
				senderKeyPair,
				recipientKeyPair.publicKey.toString("hex"),
			);

			// when
			const [aliceState1, headerA1, messageA1] = RatchetEncrypt(
				aliceState0,
				"Hi Bob!",
				ad,
			);
			const [aliceState2, headerA2, messageA2] = RatchetEncrypt(
				aliceState1,
				"Hi Bob 2!",
				ad,
			);
			const [aliceState3, headerA3, messageA3] = RatchetEncrypt(
				aliceState2,
				"Hi Bob 3!",
				ad,
			);
			const [aliceState4, headerA4, messageA4] = RatchetEncrypt(
				aliceState3,
				"Hi Bob 4!",
				ad,
			);
			const [aliceState5, headerA5, messageA5] = RatchetEncrypt(
				aliceState4,
				"Hi Bob 5!",
				ad,
			);
			// and
			const [bobState1, messageB1] = RatchetDecrypt(
				bobState0,
				headerA2,
				messageA2,
				ad,
			);
			const [bobState2, messageB2] = RatchetDecrypt(
				bobState1,
				headerA5,
				messageA5,
				ad,
			);
			const [bobState3, messageB3] = RatchetDecrypt(
				bobState2,
				headerA4,
				messageA4,
				ad,
			);
			const [bobState4, messageB4] = RatchetDecrypt(
				bobState3,
				headerA3,
				messageA3,
				ad,
			);
			const [bobState5, messageB5] = RatchetDecrypt(
				bobState4,
				headerA1,
				messageA1,
				ad,
			);
			// then
			expect(messageB1).toEqual("Hi Bob 2!");
			expect(messageB2).toEqual("Hi Bob 5!");
			expect(messageB3).toEqual("Hi Bob 4!");
			expect(messageB4).toEqual("Hi Bob 3!");
			expect(messageB5).toEqual("Hi Bob!");

			// when
			const [bobState6, headerB6, messageB6] = RatchetEncrypt(
				bobState5,
				"Hi Alice!",
				ad,
			);
			const [bobState7, headerB7, messageB7] = RatchetEncrypt(
				bobState6,
				"Hi Alice 2!",
				ad,
			);
			const [bobState8, headerB8, messageB8] = RatchetEncrypt(
				bobState7,
				"Hi Alice 3!",
				ad,
			);
			const [bobState9, headerB9, messageB9] = RatchetEncrypt(
				bobState8,
				"Hi Alice 4!",
				ad,
			);
			const [, headerB10, messageB10] = RatchetEncrypt(
				bobState9,
				"Hi Alice 5!",
				ad,
			);
			// and
			const [aliceState6, messageA6] = RatchetDecrypt(
				aliceState5,
				headerB7,
				messageB7,
				ad,
			);
			const [aliceState7, messageA7] = RatchetDecrypt(
				aliceState6,
				headerB10,
				messageB10,
				ad,
			);
			const [aliceState8, messageA8] = RatchetDecrypt(
				aliceState7,
				headerB9,
				messageB9,
				ad,
			);
			const [aliceState9, messageA9] = RatchetDecrypt(
				aliceState8,
				headerB8,
				messageB8,
				ad,
			);
			const [, messageA10] = RatchetDecrypt(
				aliceState9,
				headerB6,
				messageB6,
				ad,
			);

			// then
			expect(messageA6).toEqual("Hi Alice 2!");
			expect(messageA7).toEqual("Hi Alice 5!");
			expect(messageA8).toEqual("Hi Alice 4!");
			expect(messageA9).toEqual("Hi Alice 3!");
			expect(messageA10).toEqual("Hi Alice!");
		});

		test("Skip a too many messages", () => {
			// given
			const bobState = InitState(
				rootKey,
				recipientKeyPair,
				senderKeyPair.publicKey.toString("hex"),
			);
			// and
			let aliceState = InitState(
				rootKey,
				senderKeyPair,
				recipientKeyPair.publicKey.toString("hex"),
			);

			for (let i = 0; i <= MAX_SKIP; i++) {
				[aliceState, ,] = RatchetEncrypt(aliceState, "Hi Bob!", ad);
			}

			// when
			const [, header, message] = RatchetEncrypt(aliceState, "Hi Bob!", ad);
			// then
			expect(() => RatchetDecrypt(bobState, header, message, ad)).toThrow(
				"Too many skipped messages!",
			);
		});
	});
});
