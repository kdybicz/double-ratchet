import type { KeyPairSyncResult } from "node:crypto";
import {
	CONCAT,
	DECRYPT,
	DH,
	ENCRYPT,
	GENERATE_DH,
	HDECRYPT,
	HEADER,
	HENCRYPT,
	type Header,
	KDF_CK,
	KDF_RK_HE,
	MAX_SKIP,
} from "./utils";

/**
 * Double Ratchet with header encryption
 */
export class DoubleRatchetHE {
	// DH Ratchet key pair (the "sending" or "self" ratchet key)
	protected DHRs: KeyPairSyncResult<Buffer, Buffer>;

	// DH Ratchet public key (the "received" or "remote" key)
	protected DHRr: string | null;

	// 32-byte Root Key
	protected RK: Buffer<ArrayBufferLike>;

	// 32-byte Chain Keys for sending and receiving
	protected CKs: Buffer<ArrayBufferLike> | null;
	protected CKr: Buffer<ArrayBufferLike> | null;

	// Message numbers for sending and receiving
	protected Ns: number;
	protected Nr: number;

	// Number of messages in previous sending chain
	protected PN: number;

	// 32-byte Header Keys for sending and receiving
	protected HKs: Buffer<ArrayBufferLike> | null;
	protected HKr: Buffer<ArrayBufferLike> | null;

	// 32-byte Next Header Keys for sending and receiving
	protected NHKs: Buffer<ArrayBufferLike>;
	protected NHKr: Buffer<ArrayBufferLike>;

	// Dictionary of skipped-over message keys, indexed by header key and message
	// number. Raises an exception if too many elements are stored.
	protected MKSKIPPED: Record<string, Buffer<ArrayBufferLike>>;

	/**
	 * Some additional shared secrets must be used to initialize the header keys:
	 *  - Alice's sending header key and Bob's next receiving header key must be
	 *     set to the same value, so that Alice's first message triggers a DH
	 *     ratchet step for Bob.
	 *  - Alice's next receiving header key and Bob's next sending header key
	 *     must be set to the same value, so that after Bob's first DH ratchet
	 *     step, Bob's next message triggers a DH ratchet step for Alice.
	 *
	 * Once Alice and Bob have agreed on SK, Bob's ratchet public key, and these
	 * additional values, Alice calls fromPublicKey() and Bob calls fromKeyPair():
	 *
	 * @param DHRs
	 * @param DHRr
	 * @param RK
	 * @param CKs
	 * @param HKs
	 * @param NHKs
	 * @param NHKr
	 */
	constructor(
		DHRs: KeyPairSyncResult<Buffer, Buffer>,
		DHRr: string | null,
		RK: Buffer<ArrayBufferLike>,
		CKs: Buffer<ArrayBufferLike> | null,
		HKs: Buffer<ArrayBufferLike> | null,
		NHKs: Buffer<ArrayBufferLike>,
		NHKr: Buffer<ArrayBufferLike>,
	) {
		this.DHRs = DHRs;
		this.DHRr = DHRr;
		this.RK = RK;
		this.CKs = CKs;
		this.CKr = null;
		this.Ns = 0;
		this.Nr = 0;
		this.PN = 0;
		this.HKs = HKs;
		this.NHKs = NHKs;
		this.HKr = null;
		this.NHKr = NHKr;
		this.MKSKIPPED = {};
	}

	public static fromPublicKey(
		sk: Buffer<ArrayBufferLike>,
		publicKey: string,
		sharedHKa: Buffer<ArrayBufferLike>,
		sharedNHKb: Buffer<ArrayBufferLike>,
	): DoubleRatchetHE {
		const DHs = GENERATE_DH();
		const DHr = publicKey;
		const [RK, CKs, NHKs] = KDF_RK_HE(sk, DH(DHs, DHr));

		return new DoubleRatchetHE(DHs, DHr, RK, CKs, sharedHKa, NHKs, sharedNHKb);
	}

	public static fromKeyPair(
		sk: Buffer<ArrayBufferLike>,
		keyPair: KeyPairSyncResult<Buffer, Buffer>,
		sharedHKa: Buffer<ArrayBufferLike>,
		sharedNHKb: Buffer<ArrayBufferLike>,
	): DoubleRatchetHE {
		return new DoubleRatchetHE(
			keyPair,
			null,
			sk,
			null,
			null,
			sharedNHKb,
			sharedHKa,
		);
	}

	/**
	 * Is called to encrypt messages with header encryption.
	 *
	 * @param plaintext
	 * @param ad is for associated data
	 * @returns
	 */
	public RatchetEncryptHE = (plaintext: string, ad: Buffer) => {
		if (this.CKs === null) {
			throw new Error("Chain Key for sending not initialized!");
		}
		if (this.HKs === null) {
			throw new Error("Header Key for sending not initialized!");
		}

		const [newCKs, mk] = KDF_CK(this.CKs);
		this.CKs = newCKs;

		const header = HEADER(this.DHRs, this.PN, this.Ns);
		const encryptedHeader = HENCRYPT(this.HKs, header);
		this.Ns += 1;

		return [
			encryptedHeader,
			ENCRYPT(mk, plaintext, CONCAT(ad, encryptedHeader)),
		];
	};

	/**
	 * Is called to decrypt messages with header encryption.
	 *
	 * @param encryptedHeader
	 * @param ciphertext
	 * @param ad is for associated data
	 * @returns
	 */
	public RatchetDecryptHE = (
		encryptedHeader: string,
		ciphertext: string,
		ad: Buffer,
	) => {
		const plaintext = this.TrySkippedMessageKeysHE(
			encryptedHeader,
			ciphertext,
			ad,
		);
		if (plaintext !== null) {
			return plaintext;
		}

		const [header, shouldRunDHRatchet] = this.DecryptHeader(encryptedHeader);
		if (shouldRunDHRatchet) {
			this.SkipMessageKeysHE(header.pn);
			this.DHRatchetHE(header);
		}

		this.SkipMessageKeysHE(header.n);

		const [newCKr, mk] = KDF_CK(this.CKr as Buffer);
		this.CKr = newCKr;
		this.Nr += 1;

		return DECRYPT(mk, ciphertext, CONCAT(ad, encryptedHeader));
	};

	protected TrySkippedMessageKeysHE = (
		encryptedHeader: string,
		ciphertext: string,
		ad: Buffer,
	): string | null => {
		for (const [idx, mk] of Object.entries(this.MKSKIPPED)) {
			const [a, b] = idx.split("-");
			const hk = Buffer.from(a, "hex");
			const n = Number.parseInt(b);

			const header = HDECRYPT(hk, encryptedHeader);
			if (header !== null && header.n === n) {
				delete this.MKSKIPPED[idx];
				return DECRYPT(mk, ciphertext, CONCAT(ad, encryptedHeader));
			}
		}
		return null;
	};

	protected DecryptHeader = (encryptedHeader: string): [Header, boolean] => {
		let header = HDECRYPT(this.HKr, encryptedHeader);
		if (header !== null) {
			return [header, false];
		}

		header = HDECRYPT(this.NHKr, encryptedHeader);
		if (header !== null) {
			return [header, true];
		}

		throw new Error("Unable to decrypt header!");
	};

	protected SkipMessageKeysHE = (until: number): void => {
		if (this.Nr + MAX_SKIP < until) {
			throw new Error("Too many skipped messages!");
		}

		if (this.CKr !== null) {
			while (this.Nr < until) {
				const [newCKr, mk] = KDF_CK(this.CKr);
				this.CKr = newCKr;
				this.MKSKIPPED[`${this.HKr?.toString("hex")}-${this.Nr}`] = mk;
				this.Nr += 1;
			}
		}
	};

	protected DHRatchetHE = (header: Header): void => {
		this.PN = this.Ns;
		this.Ns = 0;
		this.Nr = 0;
		this.HKs = this.NHKs;
		this.HKr = this.NHKr;
		this.DHRr = header.dh;
		[this.RK, this.CKr, this.NHKr] = KDF_RK_HE(
			this.RK,
			DH(this.DHRs, this.DHRr as string),
		);
		this.DHRs = GENERATE_DH();
		[this.RK, this.CKs, this.NHKs] = KDF_RK_HE(
			this.RK,
			DH(this.DHRs, this.DHRr as string),
		);
	};
}
