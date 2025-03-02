import { GENERATE_DH, type Header, MAX_SKIP } from "../../src/utils";
import {
	InitInitiatorState,
	InitResponderState,
	RatchetDecrypt,
	RatchetEncrypt,
	type State,
} from "../../src/x3dh/ratchet";

describe("X3DH Double Ratchet", () => {
	const initiatorKeyPair = GENERATE_DH();
	const responderKeyPair = GENERATE_DH();

	const rootKey = Buffer.from("some random key some random key!");
	const ad = Buffer.from("random associated data");

	test("Initiator sends first messages", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);

		// when - sending first message
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"plain text message",
			ad,
		);
		// then
		expect(aliceState1.Ns).toEqual(1); // sent one message
		expect(aliceState1.Nr).toEqual(0);
		expect(aliceState1.PN).toEqual(0);
		expect(aliceState1.DHs).toEqual(aliceState0.DHs); // sender key haven't changed
		expect(aliceState1.CKs).not.toEqual(aliceState0.CKs); // sender chain key was rotated
		expect(aliceState1.CKr).toBeUndefined(); // recipient chain key was not initialized yet
		// and
		expect(aliceHeader1.dh).toEqual(initiatorKeyPair.publicKey.toString("hex")); // use sender public key
		expect(aliceHeader1.n).toEqual(0); // first message number, starting from zero
		expect(aliceHeader1.pn).toEqual(0);
		// and
		expect(aliceMessage1).not.toEqual("plain text message");

		// when - sending second message
		const [aliceState2, aliceHeader2, aliceMessage2] = RatchetEncrypt(
			aliceState1,
			"plain text message",
			ad,
		);
		// then
		expect(aliceState2.Ns).toEqual(2); // sent two messages
		expect(aliceState2.Nr).toEqual(0);
		expect(aliceState2.PN).toEqual(0);
		expect(aliceState2.DHs).toEqual(aliceState1.DHs); // sender key haven't changed
		expect(aliceState2.CKs).not.toEqual(aliceState1.CKs); // sender chain key was rotated
		expect(aliceState2.CKr).toBeUndefined(); // recipient chain key was not initialized yet
		// and
		expect(aliceHeader2.dh).toEqual(initiatorKeyPair.publicKey.toString("hex")); // use sender public key
		expect(aliceHeader2.n).toEqual(1); // second message number, starting from zero
		expect(aliceHeader2.pn).toEqual(0);
		// and
		expect(aliceMessage2).not.toEqual(aliceMessage1); // same messages, but encrypted with different Message Key

		// when - sending second message
		const [aliceState3, aliceHeader3, aliceMessage3] = RatchetEncrypt(
			aliceState2,
			"plain text message",
			ad,
		);
		// then
		expect(aliceState3.Ns).toEqual(3); // sent three messages
		expect(aliceState3.Nr).toEqual(0);
		expect(aliceState3.PN).toEqual(0);
		expect(aliceState3.DHs).toEqual(aliceState2.DHs); // sender key haven't changed
		expect(aliceState3.CKs).not.toEqual(aliceState2.CKs); // sender chain key was rotated
		expect(aliceState3.CKr).toBeUndefined(); // recipient chain key was not initialized yet
		// and
		expect(aliceHeader3.dh).toEqual(initiatorKeyPair.publicKey.toString("hex")); // use sender public key
		expect(aliceHeader3.n).toEqual(2); // third message number, starting from zero
		expect(aliceHeader3.pn).toEqual(0);
		// and
		expect(aliceMessage3).not.toEqual(aliceMessage1); // same messages, but encrypted with different Message Key
		expect(aliceMessage3).not.toEqual(aliceMessage2); // same messages, but encrypted with different Message Key
	});

	test("Recipient receive first messages", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		// and
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"plain text message",
			ad,
		);
		const [aliceState2, aliceHeader2, aliceMessage2] = RatchetEncrypt(
			aliceState1,
			"plain text message",
			ad,
		);
		const [, aliceHeader3, aliceMessage3] = RatchetEncrypt(
			aliceState2,
			"plain text message",
			ad,
		);
		// and
		const bobState0 = InitResponderState(rootKey, responderKeyPair);

		// when
		const [bobState1, bobMessage1] = RatchetDecrypt(
			bobState0,
			aliceHeader1,
			aliceMessage1,
			ad,
		);
		// then
		expect(bobState1.Ns).toEqual(0);
		expect(bobState1.Nr).toEqual(1); // received one message
		expect(bobState1.PN).toEqual(0);
		expect(bobState1.DHr).not.toBeUndefined(); // recipient key was initialized
		// and
		expect(bobMessage1).toEqual("plain text message");

		// when
		const [bobState2, bobMessage2] = RatchetDecrypt(
			bobState1,
			aliceHeader2,
			aliceMessage2,
			ad,
		);
		// then
		expect(bobState2.Ns).toEqual(0);
		expect(bobState2.Nr).toEqual(2); // received two messages
		expect(bobState2.PN).toEqual(0);
		expect(bobState2.DHr).toEqual(bobState1.DHr); // recipient key haven't changed
		// and
		expect(bobMessage2).toEqual("plain text message");

		// when
		const [bobState3, bobMessage3] = RatchetDecrypt(
			bobState2,
			aliceHeader3,
			aliceMessage3,
			ad,
		);
		// then
		expect(bobState3.Ns).toEqual(0);
		expect(bobState3.Nr).toEqual(3); // received three messages
		expect(bobState3.PN).toEqual(0);
		expect(bobState3.DHr).toEqual(bobState2.DHr); // recipient key haven't changed
		// and
		expect(bobMessage3).toEqual("plain text message");
	});

	test("Initiator receive first messages out of order", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"plain text message",
			ad,
		);
		// and
		const bobState0 = InitResponderState(rootKey, responderKeyPair);
		const [bobState1, bobMessage1] = RatchetDecrypt(
			bobState0,
			aliceHeader1,
			aliceMessage1,
			ad,
		);
		// and
		const [bobState2, bobHeader2, bobMessage2] = RatchetEncrypt(
			bobState1,
			"plain text message 1",
			ad,
		);
		const [bobState3, bobHeader3, bobMessage3] = RatchetEncrypt(
			bobState2,
			"plain text message 2",
			ad,
		);
		const [bobState4, bobHeader4, bobMessage4] = RatchetEncrypt(
			bobState3,
			"plain text message 3",
			ad,
		);

		// when - receiving third message first
		const [aliceState2, aliceMessage2] = RatchetDecrypt(
			aliceState1,
			bobHeader4,
			bobMessage4,
			ad,
		);
		// then
		expect(aliceState2.Ns).toEqual(0);
		expect(aliceState2.Nr).toEqual(3); // received message counter set to three messages, even though two are missing
		expect(aliceState2.PN).toEqual(1);
		expect(aliceState2.DHr).not.toBeUndefined(); // recipient key was initialized
		// and
		expect(aliceMessage2).toEqual("plain text message 3");

		// when - receiving first message second
		const [aliceState3, aliceMessage3] = RatchetDecrypt(
			aliceState2,
			bobHeader2,
			bobMessage2,
			ad,
		);
		// then
		expect(aliceState3.Ns).toEqual(0);
		expect(aliceState3.Nr).toEqual(3); // received message counter set to three messages, even though two are missing
		expect(aliceState3.PN).toEqual(1);
		expect(aliceState3.DHr).not.toBeUndefined(); // recipient key was initialized
		// and
		expect(aliceMessage3).toEqual("plain text message 1");

		// when - receiving second message third
		const [aliceState4, aliceMessage4] = RatchetDecrypt(
			aliceState3,
			bobHeader3,
			bobMessage3,
			ad,
		);
		// then
		expect(aliceState4.Ns).toEqual(0);
		expect(aliceState4.Nr).toEqual(3); // received message counter set to three messages, even though two are missing
		expect(aliceState4.PN).toEqual(1);
		expect(aliceState4.DHr).not.toBeUndefined(); // recipient key was initialized
		// and
		expect(aliceMessage4).toEqual("plain text message 2");
	});

	test("Recipient receive first messages out of order", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		// and
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"plain text message",
			ad,
		);
		const [aliceState2, aliceHeader2, aliceMessage2] = RatchetEncrypt(
			aliceState1,
			"plain text message",
			ad,
		);
		const [, aliceHeader3, aliceMessage3] = RatchetEncrypt(
			aliceState2,
			"plain text message",
			ad,
		);
		// and
		const bobState0 = InitResponderState(rootKey, responderKeyPair);

		// when - receiving third message first
		const [bobState1, bobMessage1] = RatchetDecrypt(
			bobState0,
			aliceHeader3,
			aliceMessage3,
			ad,
		);
		// then
		expect(bobState1.Ns).toEqual(0);
		expect(bobState1.Nr).toEqual(3); // received message counter set to three messages, even though two are missing
		expect(bobState1.PN).toEqual(0);
		expect(bobState1.DHr).not.toBeUndefined(); // recipient key was initialized
		// and
		expect(bobMessage1).toEqual("plain text message");

		// when - receiving first message second
		const [bobState2, bobMessage2] = RatchetDecrypt(
			bobState1,
			aliceHeader1,
			aliceMessage1,
			ad,
		);
		// then
		expect(bobState2.Ns).toEqual(0);
		expect(bobState2.Nr).toEqual(3); // received message counter still on three
		expect(bobState2.PN).toEqual(0);
		expect(bobState2.DHr).toEqual(bobState1.DHr); // recipient key haven't changed
		// and
		expect(bobMessage2).toEqual("plain text message");

		// when - receiving second message third
		const [bobState3, bobMessage3] = RatchetDecrypt(
			bobState2,
			aliceHeader2,
			aliceMessage2,
			ad,
		);
		// then
		expect(bobState3.Ns).toEqual(0);
		expect(bobState3.Nr).toEqual(3); // received message counter still on three
		expect(bobState3.PN).toEqual(0);
		expect(bobState3.DHr).toEqual(bobState2.DHr); // recipient key haven't changed
		// and
		expect(bobMessage3).toEqual("plain text message");
	});

	test("Initiator engages ratchet after each response to new message sent", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		// and
		const bobState0 = InitResponderState(rootKey, responderKeyPair);
		// and - initiator sends first message
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"plain text message",
			ad,
		);

		// expect - checking initial state
		expect(aliceState1.Ns).toEqual(1); // sent one message
		expect(aliceState1.Nr).toEqual(0);
		expect(aliceState1.PN).toEqual(0);
		expect(aliceState1.DHs).toEqual(aliceState0.DHs); // sender key haven't changed
		expect(aliceState1.CKs).not.toEqual(aliceState0.CKs); // sender chain key was rotated
		expect(aliceState1.CKr).toBeUndefined(); // recipient chain key was not initialized yet
		// and
		expect(aliceHeader1.dh).toEqual(initiatorKeyPair.publicKey.toString("hex")); // use sender public key
		expect(aliceHeader1.n).toEqual(0); // first message number, starting from zero
		expect(aliceHeader1.pn).toEqual(0);

		// when - responder receives a message
		const [bobState1, bobMessage1] = RatchetDecrypt(
			bobState0,
			aliceHeader1,
			aliceMessage1,
			ad,
		);
		// then - responder sends a response
		const [bobState2, bobHeader2, bobMessage2] = RatchetEncrypt(
			bobState1,
			"plain text message",
			ad,
		);

		// when - initiator received new response
		const [aliceState2, aliceMessage2] = RatchetDecrypt(
			aliceState1,
			bobHeader2,
			bobMessage2,
			ad,
		);
		// then - initiator cranks the ratchet
		expect(aliceState2.Ns).toEqual(0);
		expect(aliceState2.Nr).toEqual(1); // received one message
		expect(aliceState2.PN).toEqual(1); // previous chain length set to one
		expect(aliceState2.DHs).not.toEqual(aliceState1.DHs); // sender key was rotated
		expect(aliceState2.DHr).toEqual(bobHeader2.dh); // recipient key updated from header
		expect(aliceState2.CKs).not.toEqual(aliceState1.CKs); // sender chain key was rotated
		expect(aliceState2.CKr).not.toEqual(aliceState1.CKr); // recipient chain key was rotated

		// when - initiator sends second message
		const [aliceState3, aliceHeader3, aliceMessage3] = RatchetEncrypt(
			aliceState2,
			"plain text message",
			ad,
		);
		// then
		expect(aliceState3.Ns).toEqual(1); // sent one message
		expect(aliceState3.Nr).toEqual(1); // received one message
		expect(aliceState3.PN).toEqual(1); // previous chain length set to one
		expect(aliceState3.DHs).toEqual(aliceState2.DHs); // sender key haven't changed
		expect(aliceState3.CKs).not.toEqual(aliceState2.CKs); // sender chain key was rotated
		expect(aliceState3.CKr).toEqual(aliceState2.CKr); // recipient chain key haven't changed
		// and
		expect(aliceHeader3.dh).not.toEqual(
			initiatorKeyPair.publicKey.toString("hex"),
		); // sender public key was rotated
		expect(aliceHeader3.dh).toEqual(aliceState2.DHs.publicKey.toString("hex"));
		expect(aliceHeader3.n).toEqual(0); // first message number in new message chain
		expect(aliceHeader3.pn).toEqual(1); // previous message chain length

		// when - responder receives a message
		const [bobState3, bobMessage3] = RatchetDecrypt(
			bobState2,
			aliceHeader3,
			aliceMessage3,
			ad,
		);
		// then - responder sends a response
		const [bobState4, bobHeader4, bobMessage4] = RatchetEncrypt(
			bobState3,
			"plain text message",
			ad,
		);

		// when - initiator received new response
		const [aliceState4, aliceMessage4] = RatchetDecrypt(
			aliceState3,
			bobHeader4,
			bobMessage4,
			ad,
		);
		// then - initiator cranks the ratchet
		expect(aliceState4.Ns).toEqual(0);
		expect(aliceState4.Nr).toEqual(1); // received one message
		expect(aliceState4.PN).toEqual(1); // previous chain length set to one
		expect(aliceState4.DHs).not.toEqual(aliceState3.DHs); // sender key was rotated
		expect(aliceState4.DHr).toEqual(bobHeader4.dh); // recipient key updated from header
		expect(aliceState4.CKs).not.toEqual(aliceState3.CKs); // sender chain key was rotated
		expect(aliceState4.CKr).not.toEqual(aliceState3.CKr); // recipient chain key was rotated

		// when - initiator sends third message
		const [aliceState5, aliceHeader5, aliceMessage5] = RatchetEncrypt(
			aliceState4,
			"plain text message",
			ad,
		);
		// then
		expect(aliceState5.Ns).toEqual(1); // sent one message
		expect(aliceState5.Nr).toEqual(1); // received one message
		expect(aliceState5.PN).toEqual(1); // previous chain length set to one
		expect(aliceState5.DHs).toEqual(aliceState4.DHs); // sender key haven't changed
		expect(aliceState5.CKs).not.toEqual(aliceState4.CKs); // sender chain key was rotated
		expect(aliceState5.CKr).toEqual(aliceState4.CKr); // recipient chain key haven't changed
		// and
		expect(aliceHeader5.dh).not.toEqual(
			initiatorKeyPair.publicKey.toString("hex"),
		); // sender public key was rotated
		expect(aliceHeader5.dh).toEqual(aliceState4.DHs.publicKey.toString("hex"));
		expect(aliceHeader5.n).toEqual(0); // first message number in new message chain
		expect(aliceHeader5.pn).toEqual(1); // previous message chain length
	});

	test("Responder engages ratchet after each response", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		// and
		const bobState0 = InitResponderState(rootKey, responderKeyPair);
		// and
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"plain text message",
			ad,
		);

		// when - responder receives first message
		const [bobState1, bobMessage1] = RatchetDecrypt(
			bobState0,
			aliceHeader1,
			aliceMessage1,
			ad,
		);
		// then - responder cranks the ratchet
		expect(bobState1.Ns).toEqual(0);
		expect(bobState1.Nr).toEqual(1); // received one message
		expect(bobState1.PN).toEqual(0);
		expect(bobState1.DHs).not.toEqual(aliceState1.DHs); // sender key was rotated
		expect(bobState1.DHr).toEqual(aliceHeader1.dh); // recipient key updated from header
		expect(bobState1.CKs).not.toEqual(aliceState1.CKs); // sender chain key was rotated
		expect(bobState1.CKr).not.toEqual(aliceState1.CKr); // recipient chain key was rotated

		// when - responder sends second message
		const [bobState2, bobHeader2, bobMessage2] = RatchetEncrypt(
			bobState1,
			"plain text message",
			ad,
		);
		// then
		expect(bobState2.Ns).toEqual(1); // sent one message
		expect(bobState2.Nr).toEqual(1); // received one message
		expect(bobState2.PN).toEqual(0);
		expect(bobState2.DHs).toEqual(bobState1.DHs); // sender key haven't changed
		expect(bobState2.CKs).not.toEqual(bobState1.CKs); // sender chain key was rotated
		expect(bobState2.CKr).toEqual(bobState1.CKr); // recipient chain key haven't changed
		// and
		expect(bobHeader2.dh).not.toEqual(
			initiatorKeyPair.publicKey.toString("hex"),
		); // sender public key was rotated
		expect(bobHeader2.dh).toEqual(bobState1.DHs.publicKey.toString("hex"));
		expect(bobHeader2.n).toEqual(0); // first message number in new message chain
		expect(bobHeader2.pn).toEqual(0); // previous message chain length

		// when - initiator receives the message
		const [aliceState2, aliceMessage2] = RatchetDecrypt(
			aliceState1,
			bobHeader2,
			bobMessage2,
			ad,
		);
		// then - initiator sends a response
		const [aliceState3, aliceHeader3, aliceMessage3] = RatchetEncrypt(
			aliceState2,
			"plain text message",
			ad,
		);

		// when - responder receives second message
		const [bobState3, bobMessage3] = RatchetDecrypt(
			bobState2,
			aliceHeader3,
			aliceMessage3,
			ad,
		);
		// then - responder cranks the ratchet
		expect(bobState3.Ns).toEqual(0);
		expect(bobState3.Nr).toEqual(1); // received one message
		expect(bobState3.PN).toEqual(1); // previous chain length set to one
		expect(bobState3.DHs).not.toEqual(aliceState3.DHs); // sender key was rotated
		expect(bobState3.DHr).toEqual(aliceHeader3.dh); // recipient key updated from header
		expect(bobState3.CKs).not.toEqual(aliceState3.CKs); // sender chain key was rotated
		expect(bobState3.CKr).not.toEqual(aliceState3.CKr); // recipient chain key was rotated

		// when - responder sends third message
		const [bobState4, bobHeader4, bobMessage4] = RatchetEncrypt(
			bobState3,
			"plain text message",
			ad,
		);
		// then
		expect(bobState4.Ns).toEqual(1); // sent one message
		expect(bobState4.Nr).toEqual(1); // received one message
		expect(bobState4.PN).toEqual(1); // previous chain length set to one
		expect(bobState4.DHs).toEqual(bobState3.DHs); // sender key haven't changed
		expect(bobState4.CKs).not.toEqual(bobState3.CKs); // sender chain key was rotated
		expect(bobState4.CKr).toEqual(bobState3.CKr); // recipient chain key haven't changed
		// and
		expect(bobHeader4.dh).not.toEqual(
			initiatorKeyPair.publicKey.toString("hex"),
		); // sender public key was rotated
		expect(bobHeader4.dh).toEqual(bobState3.DHs.publicKey.toString("hex"));
		expect(bobHeader4.n).toEqual(0); // first message number in new message chain
		expect(bobHeader4.pn).toEqual(1); // previous message chain length
	});

	test("Initiator skipped a too many messages", () => {
		// given
		const aliceState0 = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		const [aliceState1, aliceHeader1, aliceMessage1] = RatchetEncrypt(
			aliceState0,
			"Hi Bob!",
			ad,
		);
		// and
		const bobState0 = InitResponderState(rootKey, responderKeyPair);
		const [bobState1, bobMessage1] = RatchetDecrypt(
			bobState0,
			aliceHeader1,
			aliceMessage1,
			ad,
		);
		// and
		let bobState2: State = bobState1;
		for (let i = 0; i <= MAX_SKIP; i++) {
			[bobState2, ,] = RatchetEncrypt(bobState2, "Hi Alice!", ad);
		}

		// when
		const [, header, message] = RatchetEncrypt(
			bobState2 as State,
			"Hi Alice!",
			ad,
		);
		// then
		expect(() => RatchetDecrypt(aliceState1, header, message, ad)).toThrow(
			"Too many skipped messages!",
		);
	});

	test("Responder skipped a too many messages", () => {
		// given
		let aliceState = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		// and
		const bobState = InitResponderState(rootKey, responderKeyPair);
		// and
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

	test("Brute-force messaging test", () => {
		// given
		let aliceState = InitInitiatorState(
			rootKey,
			initiatorKeyPair,
			responderKeyPair.publicKey.toString("hex"),
		);
		let aliceHeader: Header = { dh: "", n: 0, pn: 0 };
		let aliceMessage = "";
		// and
		let bobState = InitResponderState(rootKey, responderKeyPair);
		let bobHeader: Header = { dh: "", n: 0, pn: 0 };
		let bobMessage = "";

		// when
		expect(() => {
			for (let i = 0; i < 10; i++) {
				const messages: [Header, string][] = [];
				for (let j = 0; j < 1 + Math.ceil(i / 2); j++) {
					[aliceState, aliceHeader, aliceMessage] = RatchetEncrypt(
						aliceState,
						"plain text message",
						ad,
					);
					messages.push([aliceHeader, aliceMessage]);
				}
				while (messages.length > 0) {
					const [aliceHeader, aliceMessage] = messages.pop() as [
						Header,
						string,
					];
					[bobState, bobMessage] = RatchetDecrypt(
						bobState,
						aliceHeader,
						aliceMessage,
						ad,
					);
				}

				for (let k = 0; k < 10 - Math.ceil(i / 2); k++) {
					[bobState, bobHeader, bobMessage] = RatchetEncrypt(
						bobState,
						"plain text message",
						ad,
					);
					messages.push([bobHeader, bobMessage]);
				}
				while (messages.length > 0) {
					const [bobHeader, bobMessage] = messages.pop() as [Header, string];
					console.log(`i: ${i} -> Header: ${JSON.stringify(bobHeader)}`);
					[aliceState, aliceMessage] = RatchetDecrypt(
						aliceState,
						bobHeader,
						bobMessage,
						ad,
					);
				}
			}
		}).not.toThrow();
	});
});
