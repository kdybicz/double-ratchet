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
} from "../utils";

export type State = {
	// DH Ratchet key pair (the "sending" or "self" ratchet key)
	readonly DHs: KeyPairSyncResult<Buffer, Buffer>;

	// DH Ratchet public key (the "received" or "remote" key)
	readonly DHr: string;

	// 32-byte Root Key
	readonly RK: Buffer<ArrayBufferLike>;

	// 32-byte Chain Keys for sending and receiving
	readonly CKs: Buffer<ArrayBufferLike>;
	readonly CKr: Buffer<ArrayBufferLike>;

	// Message numbers for sending and receiving
	readonly Ns: number;
	readonly Nr: number;

	// Number of messages in previous sending chain
	readonly PN: number;

	// Dictionary of skipped-over message keys, indexed by ratchet public key and
	// message number. Raises an exception if too many elements are stored.
	readonly MKSKIPPED: Record<string, Buffer<ArrayBufferLike>>;
};

/**
 * Function initialize the state object, based on DH Key Pair of the sender,
 * DH Public Key of the recipient and agreed Secret Key.
 *
 * @param sk
 * @param senderKeyPair
 * @param recipientPublicKey
 * @returns
 */
export const InitState = (
	sk: Buffer<ArrayBufferLike>,
	senderKeyPair: KeyPairSyncResult<Buffer, Buffer>,
	recipientPublicKey: string,
): State => {
	const DHs = senderKeyPair;
	const DHr = recipientPublicKey;
	const [RK, CK] = KDF_RK(sk, DH(DHs, DHr));

	return {
		DHs,
		DHr,
		RK,
		CKs: CK,
		CKr: CK,
		Ns: 0,
		Nr: 0,
		PN: 0,
		MKSKIPPED: {},
	};
};

/**
 * Function returns new state based on the oldState with new values provided
 * in the newPartialState.
 *
 * @param oldState
 * @param newPartialState
 * @returns
 */
export const RotateState = (
	oldState: State,
	newPartialState: Partial<State>,
) => {
	return {
		...oldState,
		...newPartialState,
	};
};

/**
 * Function called to encrypt messages. It performs a symmetric-key
 * ratchet step, then encrypts the message with the resulting message key.
 * In addition to the message's plaintext it takes an ad byte sequence which
 * is prepended to the header to form the associated data for the underlying
 * AEAD encryption.
 *
 * @param state
 * @param plaintext
 * @param ad is for associated data
 * @returns
 */
export const RatchetEncrypt = (
	state: State,
	plaintext: string,
	ad: Buffer,
): [State, Header, string] => {
	if (state.CKs === null) {
		throw new Error("Chain Key for sending not initialized!");
	}

	const [newCKs, mk] = KDF_CK(state.CKs);

	const header = HEADER(state.DHs, state.PN, state.Ns);

	const newState = RotateState(state, {
		CKs: newCKs,
		Ns: state.Ns + 1,
	});

	return [newState, header, ENCRYPT(mk, plaintext, CONCAT(ad, header))];
};

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
 * @param state
 * @param header
 * @param ciphertext
 * @param ad is for associated data
 * @returns
 */
export const RatchetDecrypt = (
	state: State,
	header: Header,
	ciphertext: string,
	ad: Buffer,
): [State, string] => {
	let currState = state;

	const plaintext = TrySkippedMessageKeys(currState, header, ciphertext, ad);
	if (plaintext !== null) {
		return [currState, plaintext];
	}

	if (header.dh !== currState.DHr) {
		currState = SkipMessageKeys(currState, header.pn);
		currState = DHRatchet(currState, header);
	}

	currState = SkipMessageKeys(state, header.n);

	const [CKr, mk] = KDF_CK(currState.CKr);
	const Nr = currState.Nr + 1;

	currState = RotateState(currState, {
		CKr,
		Nr,
	});

	return [currState, DECRYPT(mk, ciphertext, CONCAT(ad, header))];
};

export const TrySkippedMessageKeys = (
	state: State,
	header: Header,
	ciphertext: string,
	ad: Buffer,
): string | null => {
	if (`${header.dh}-${header.n}` in state.MKSKIPPED) {
		const mk = state.MKSKIPPED[`${header.dh}-${header.n}`];
		delete state.MKSKIPPED[`${header.dh}-${header.n}`];

		return DECRYPT(mk, ciphertext, CONCAT(ad, header));
	}

	return null;
};

export const SkipMessageKeys = (state: State, until: number): State => {
	if (state.Nr + MAX_SKIP < until) {
		throw new Error("Too many skipped messages!");
	}

	if (state.CKr !== null) {
		let newState = state;
		while (newState.Nr < until) {
			const [CKr, mk] = KDF_CK(newState.CKr);
			const MKSKIPPED = {
				...newState.MKSKIPPED,
				[`${newState.DHr}-${newState.Nr}`]: mk,
			};
			const Nr = newState.Nr + 1;

			newState = RotateState(newState, {
				CKr,
				Nr,
				MKSKIPPED,
			});
		}

		return newState;
	}

	return state;
};

const DHRatchet = (state: State, header: Header): State => {
	const PN = state.Ns;
	const Ns = 0;
	const Nr = 0;
	const DHr = header.dh;
	const [RK1, CKr] = KDF_RK(state.RK, DH(state.DHs, DHr));
	const DHs = GENERATE_DH();
	const [RK2, CKs] = KDF_RK(RK1, DH(DHs, DHr));

	return RotateState(state, {
		DHs,
		DHr,
		RK: RK2,
		CKs,
		CKr,
		Ns,
		Nr,
		PN,
	});
};
