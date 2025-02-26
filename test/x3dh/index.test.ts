import { Client, type PrekeyBundle } from "../../src/x3dh/client";
import { Server } from "../../src/x3dh/server";

describe("X3DH", () => {
	test("Prekey bundle includes OTP until the are not all used", () => {
		// given
		const server = new Server();
		// and
		new Client(server, "Alice");
		new Client(server, "Bob");

		// expect
		let bundle: PrekeyBundle;
		for (let i = 0; i < 10; i++) {
			bundle = server.fetchPrekeyBundle("Alice");

			expect(bundle.oneTimePrekey).not.toBeUndefined();
		}

		// when
		bundle = server.fetchPrekeyBundle("Alice");
		// then
		expect(bundle.oneTimePrekey).toBeUndefined();

		// expect
		for (let i = 0; i < 10; i++) {
			bundle = server.fetchPrekeyBundle("Bob");

			expect(bundle.oneTimePrekey).not.toBeUndefined();
		}

		// when
		bundle = server.fetchPrekeyBundle("Bob");
		// then
		expect(bundle.oneTimePrekey).toBeUndefined();
	});

	test("Alice sends first message to Bob, Bob receives it successfully", () => {
		// given
		const server = new Server();
		// and
		const alice = new Client(server, "Alice");
		const bob = new Client(server, "Bob");

		// when
		alice.sendMessage("Bob", "message encrypted with SK and AD");
		// then
		expect(bob.fetchMessages()).toEqual(["message encrypted with SK and AD"]);
	});

	test("Alice sends couple of message to Bob, Bob receives them all at once successfully", () => {
		// given
		const server = new Server();
		// and
		const alice = new Client(server, "Alice");
		const bob = new Client(server, "Bob");

		// when
		alice.sendMessage("Bob", "message encrypted with SK and AD");
		alice.sendMessage("Bob", "message encrypted with SK and AD 2");
		alice.sendMessage("Bob", "message encrypted with SK and AD 3");
		// then
		expect(bob.fetchMessages()).toEqual([
			"message encrypted with SK and AD",
			"message encrypted with SK and AD 2",
			"message encrypted with SK and AD 3",
		]);
	});

	test("Alice and Bob sends messages back and forth", () => {
		// given
		const server = new Server();
		// and
		const alice = new Client(server, "Alice");
		const bob = new Client(server, "Bob");

		// when
		alice.sendMessage("Bob", "message encrypted with SK and AD");
		alice.sendMessage("Bob", "message encrypted with SK and AD 2");
		// then
		expect(bob.fetchMessages()).toEqual([
			"message encrypted with SK and AD",
			"message encrypted with SK and AD 2",
		]);

		// when
		bob.sendMessage("Alice", "message encrypted with SK and AD");
		bob.sendMessage("Alice", "message encrypted with SK and AD 2");
		// then
		expect(alice.fetchMessages()).toEqual([
			"message encrypted with SK and AD",
			"message encrypted with SK and AD 2",
		]);

		// when
		alice.sendMessage("Bob", "message encrypted with SK and AD 3");
		alice.sendMessage("Bob", "message encrypted with SK and AD 4");
		// then
		expect(bob.fetchMessages()).toEqual([
			"message encrypted with SK and AD 3",
			"message encrypted with SK and AD 4",
		]);

		// when
		bob.sendMessage("Alice", "message encrypted with SK and AD 3");
		bob.sendMessage("Alice", "message encrypted with SK and AD 4");
		// then
		expect(alice.fetchMessages()).toEqual([
			"message encrypted with SK and AD 3",
			"message encrypted with SK and AD 4",
		]);
	});
});
