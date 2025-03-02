import type { KeyPairSyncResult } from "node:crypto";
import {
	CONCAT,
	DECRYPT,
	DH,
	ENCRYPT,
	GENERATE_DH,
	HEADER,
	type Header,
	KDF_CK,
	KDF_RK,
	MAX_SKIP,
} from "./utils";

/**
 * Double Ratchet algorithm
 */
export class DoubleRatchet {
	// DH Ratchet key pair (the "sending" or "self" ratchet key)
	protected DHs: KeyPairSyncResult<Buffer, Buffer>;

	// DH Ratchet public key (the "received" or "remote" key)
	protected DHr: string | null;

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

	// Dictionary of skipped-over message keys, indexed by ratchet public key and
	// message number. Raises an exception if too many elements are stored.
	protected MKSKIPPED: Record<string, Buffer<ArrayBufferLike>>;

	/**
	 * Prior to initialization both parties must use some key agreement protocol
	 * to agree on a 32-byte shared secret key SK and Bob's ratchet public key.
	 * These values will be used to populate Alice's sending chain key and Bob's
	 * root key. Bob's chain keys and Alice's receiving chain key will be left
	 * empty, since they are populated by each party's first DH ratchet step.
	 *
	 * (This assumes Alice begins sending messages first, and Bob doesn't send
	 * messages until he has received one of Alice's messages. To allow Bob to
	 * send messages immediately after initialization Bob's sending chain key and
	 * Alice's receiving chain key could be initialized to a shared secret. For
	 * the sake of simplicity we won't consider this further.)
	 *
	 * Once Alice and Bob have agreed on SK and Bob's ratchet public key, Alice
	 * calls fromPublicKey() and Bob calls fromKeyPair().
	 *
	 * @param DHs
	 * @param DHr
	 * @param RK
	 * @param CKs
	 */
	constructor(
		DHs: KeyPairSyncResult<Buffer, Buffer>,
		DHr: string | null,
		RK: Buffer<ArrayBufferLike>,
		CKs: Buffer<ArrayBufferLike> | null,
		CKr: Buffer<ArrayBufferLike> | null,
	) {
		this.DHs = DHs;
		this.DHr = DHr;
		this.RK = RK;
		this.CKs = CKs;
		this.CKr = CKr;
		this.Ns = 0;
		this.Nr = 0;
		this.PN = 0;
		this.MKSKIPPED = {};
	}

	public static fromInitiatorSide(
		sk: Buffer<ArrayBufferLike>,
		keyPair: KeyPairSyncResult<Buffer, Buffer>,
		publicKey: string,
	): DoubleRatchet {
		const DHs = keyPair;
		const DHr = publicKey;
		const [RK, CKs] = KDF_RK(sk, DH(DHs, DHr));

		return new DoubleRatchet(DHs, DHr, RK, CKs, CKs);
	}

	public static fromResponderSide(
		sk: Buffer<ArrayBufferLike>,
		keyPair: KeyPairSyncResult<Buffer, Buffer>,
	): DoubleRatchet {
		return new DoubleRatchet(keyPair, null, sk, null, null);
	}

	/**
	 * is called to encrypt messages. This function performs a symmetric-key
	 * ratchet step, then encrypts the message with the resulting message key.
	 * In addition to the message's plaintext it takes an ad byte sequence which
	 * is prepended to the header to form the associated data for the underlying
	 * AEAD encryption.
	 *
	 * @param plaintext
	 * @param ad is for associated data
	 * @returns
	 */
	public RatchetEncrypt(plaintext: string, ad: Buffer): [Header, string] {
		if (this.CKs === null) {
			throw new Error("Chain Key for sending not initialized!");
		}

		const [newCKs, mk] = KDF_CK(this.CKs);
		this.CKs = newCKs;

		const header = HEADER(this.DHs, this.PN, this.Ns);
		this.Ns += 1;

		return [header, ENCRYPT(mk, plaintext, CONCAT(ad, header))];
	}

	/**
	 * This function does the following:
	 * - If the message corresponds to a skipped message key this function
	 *    decrypts the message, deletes the message key, and returns.
	 * - Otherwise, if a new ratchet key has been received this function stores
	 *    any skipped message keys from the receiving chain and performs a DH
	 *    ratchet step to replace the sending and receiving chains.
	 * - This function then stores any skipped message keys from the current
	 *    receiving chain, performs a symmetric-key ratchet step to derive the
	 *    relevant message key and next chain key, and decrypts the message.
	 *
	 * If an exception is raised (e.g. message authentication failure) then the
	 * message is discarded and changes to the state object are discarded.
	 * Otherwise, the decrypted plaintext is accepted and changes to the state
	 * object are stored.
	 *
	 * @param header
	 * @param ciphertext
	 * @param ad is for associated data
	 * @returns
	 */
	public RatchetDecrypt(
		header: Header,
		ciphertext: string,
		ad: Buffer,
	): string {
		const plaintext = this.TrySkippedMessageKeys(header, ciphertext, ad);
		if (plaintext !== null) {
			return plaintext;
		}

		if (header.dh !== this.DHr) {
			this.SkipMessageKeys(header.pn);
			this.DHRatchet(header);
		}

		this.SkipMessageKeys(header.n);

		const [newCKr, mk] = KDF_CK(this.CKr as Buffer);
		this.CKr = newCKr;
		this.Nr += 1;

		return DECRYPT(mk, ciphertext, CONCAT(ad, header));
	}

	protected TrySkippedMessageKeys(
		header: Header,
		ciphertext: string,
		ad: Buffer,
	): string | null {
		if (`${header.dh}-${header.n}` in this.MKSKIPPED) {
			const mk = this.MKSKIPPED[`${header.dh}-${header.n}`];
			delete this.MKSKIPPED[`${header.dh}-${header.n}`];

			return DECRYPT(mk, ciphertext, CONCAT(ad, header));
		}

		return null;
	}

	protected SkipMessageKeys(until: number): void {
		if (this.Nr + MAX_SKIP < until) {
			throw new Error("Too many skipped messages!");
		}

		if (this.CKr !== null) {
			while (this.Nr < until) {
				const [newCKr, mk] = KDF_CK(this.CKr);
				this.CKr = newCKr;
				this.MKSKIPPED[`${this.DHr}-${this.Nr}`] = mk;
				this.Nr += 1;
			}
		}
	}

	protected DHRatchet(header: Header): void {
		this.PN = this.Ns;
		this.Ns = 0;
		this.Nr = 0;
		this.DHr = header.dh;
		[this.RK, this.CKr] = KDF_RK(this.RK, DH(this.DHs, this.DHr as string));
		this.DHs = GENERATE_DH();
		[this.RK, this.CKs] = KDF_RK(this.RK, DH(this.DHs, this.DHr as string));
	}
}
