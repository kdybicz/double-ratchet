import { DoubleRatchet } from "../src";
import { GENERATE_DH } from "../src/utils";

describe("double ratchet", () => {
	test("Initialize with recipients public key, able to send a message", () => {
		// given
		const rootKey = Buffer.from("some random key some random key!");
		// and
		const keyPair = GENERATE_DH();

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
		// given
		const rootKey = Buffer.from("some random key some random key!");
		// and
		const keyPair = GENERATE_DH();

		// when
		const ratchet = DoubleRatchet.fromKeyPair(rootKey, keyPair);
		// then
		expect(() =>
			ratchet.RatchetEncrypt("plain text message", Buffer.from("")),
		).toThrow("Chain Keys for sending not initialized!");
	});
});
