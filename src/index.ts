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

	public RatchetEncrypt(
		plaintext: string,
		associatedData: Buffer,
	): [Header, string] {
		if (this.CKs === null) {
			throw new Error("Chain Keys for sending not initialized!");
		}

		const [newCKs, mk] = KDF_CK(this.CKs);
		this.CKs = newCKs;

		const header = HEADER(this.DHs, this.PN, this.Ns);
		this.Ns += 1;

		return [header, ENCRYPT(mk, plaintext, CONCAT(associatedData, header))];
	}

	public RatchetDecrypt(
		header: Header,
		ciphertext: string,
		associatedData: Buffer,
	) {
		if (this.CKr === null) {
			throw new Error("Chain Keys for receiving not initialized!");
		}

		const plaintext = this.TrySkippedMessageKeys(
			header,
			ciphertext,
			associatedData,
		);
		if (plaintext !== null) {
			return plaintext;
		}

		if (header.dh !== this.DHr) {
			this.SkipMessageKeys(header.pn);
			this.DHRatchet(header);
		}

		this.SkipMessageKeys(header.n);

		const [newCKr, mk] = KDF_CK(this.CKr);
		this.CKr = newCKr;
		this.Nr += 1;

		return DECRYPT(mk, ciphertext, CONCAT(associatedData, header));
	}

	protected TrySkippedMessageKeys(
		header: Header,
		ciphertext: string,
		associatedData: Buffer,
	): string | null {
		if (`${header.dh}-${header.n}` in this.MKSKIPPED) {
			const mk = this.MKSKIPPED[`${header.dh}-${header.n}`];
			delete this.MKSKIPPED[`${header.dh}-${header.n}`];

			return DECRYPT(mk, ciphertext, CONCAT(associatedData, header));
		}

		return null;
	}

	protected SkipMessageKeys(until: number) {
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

	protected DHRatchet(header: Header) {
		this.PN = this.Ns;
		this.Ns = 0;
		this.Nr = 0;
		this.DHr = header.dh;
		[this.RK, this.CKr] = KDF_RK(this.RK, DH(this.DHs, this.DHr as string));
		this.DHs = GENERATE_DH();
		[this.RK, this.CKs] = KDF_RK(this.RK, DH(this.DHs, this.DHr as string));
	}

	public static fromPublicKey(
		sk: Buffer<ArrayBufferLike>,
		publicKey: string,
	): DoubleRatchet {
		const cls = new DoubleRatchet();
		cls.DHs = GENERATE_DH();
		cls.DHr = publicKey;
		[cls.RK, cls.CKs] = KDF_RK(sk, DH(cls.DHs, cls.DHr));
		cls.CKr = null;
		cls.Ns = 0;
		cls.Nr = 0;
		cls.PN = 0;
		cls.MKSKIPPED = {};
		return cls;
	}

	public static fromKeyPair(
		sk: Buffer<ArrayBufferLike>,
		keyPair: KeyPairSyncResult<Buffer, Buffer>,
	): DoubleRatchet {
		const cls = new DoubleRatchet();
		cls.DHs = keyPair;
		cls.DHr = null;
		cls.RK = sk;
		cls.CKs = null;
		cls.CKr = null;
		cls.Ns = 0;
		cls.Nr = 0;
		cls.PN = 0;
		cls.MKSKIPPED = {};
		return cls;
	}
}
