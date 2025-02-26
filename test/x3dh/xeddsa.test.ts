import { randomBytes } from "node:crypto";
import { GENERATE_DH } from "../../src/utils";
import {
	EdwardsPoint,
	calculateKeyPair,
	sign,
	verify,
} from "../../src/x3dh/xeddsa";

describe("Montgomery curve", () => {
	const x25519KeyPairDer = GENERATE_DH();

	test("mapping x25519 private key and public key yields in the same ED25519 public key", () => {
		// when
		const { publicKey: A, privateKey: a } = calculateKeyPair(
			x25519KeyPairDer.privateKey,
		);
		// and
		const P = EdwardsPoint.fromMontgomery(
			x25519KeyPairDer.publicKey,
		).compress();
		// then
		expect(A.byteLength).toEqual(32);
		expect(a.byteLength).toEqual(32);
		expect(P.byteLength).toEqual(32);
		// and
		expect(A).toEqual(P);
	});

	test("generate and verify XEdDSA signature", () => {
		// given
		const M = Buffer.from("Example message to sign", "utf8");
		const Z = randomBytes(64);

		// when
		const signature = sign(x25519KeyPairDer.privateKey, M, Z);
		// when
		const valid = verify(x25519KeyPairDer.publicKey, M, signature);
		expect(valid).toEqual(true);
	});
});
