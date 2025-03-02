import { type KeyPairSyncResult, randomUUID } from "node:crypto";

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

// TODO: workout when what state should be applied
export enum Status {
	empty = "empty",
	active = "active",
	accepted = "accepted",
	rejected = "rejected",
}

export enum Role {
	initiator = "initiator",
	responder = "responder",
}

export interface ReadonlyState {
	// ID of the current session
	readonly sessionid: string;

	// The role of the participant, it is either initiator or responder.
	readonly role: Role;
}

export interface ModifiableState {
	// Status of the session. accepted or rejected means that it has fully
	// completed the computations and accepted or rejected the outcome
	readonly status: Status;

	// DH Ratchet key pair (the "sending" or "self" ratchet key)
	readonly DHs: KeyPairSyncResult<Buffer, Buffer>;

	// DH Ratchet public key (the "received" or "remote" key)
	readonly DHr?: string;

	// 32-byte Root Key
	readonly RK: Buffer<ArrayBufferLike>;

	// 32-byte Chain Keys for sending and receiving
	readonly CKs?: Buffer<ArrayBufferLike>;
	readonly CKr?: Buffer<ArrayBufferLike>;

	// Message numbers for sending and receiving
	readonly Ns: number;
	readonly Nr: number;

	// Number of messages in previous sending chain
	readonly PN: number;

	// Dictionary of skipped-over message keys, indexed by ratchet public key and
	// message number. Raises an exception if too many elements are stored.
	readonly MKSKIPPED: Record<string, Buffer<ArrayBufferLike>>;
}

export interface State extends ReadonlyState, ModifiableState {
	readonly version: number;
	readonly prev?: State;
}

/**
 * Function initialize the state object, based on DH Key Pair of the sender,
 * DH Public Key of the recipient and agreed Secret Key.
 *
 * @param sk
 * @param senderKeyPair
 * @param recipientPublicKey
 * @returns
 */
export const InitInitiatorState = (
	sk: Buffer<ArrayBufferLike>,
	senderKeyPair: KeyPairSyncResult<Buffer, Buffer>,
	recipientPublicKey: string,
): State => {
	const role = Role.initiator;
	const status = Status.empty;

	const DHs = senderKeyPair;
	const DHr = recipientPublicKey;
	const [RK, CKs] = KDF_RK(sk, DH(DHs, DHr));

	return {
		sessionid: randomUUID(),
		role,
		status,
		DHs,
		DHr,
		RK,
		CKs,
		Ns: 0,
		Nr: 0,
		PN: 0,
		MKSKIPPED: {},
		version: 0,
	};
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
export const InitResponderState = (
	sk: Buffer<ArrayBufferLike>,
	senderKeyPair: KeyPairSyncResult<Buffer, Buffer>,
): State => {
	const role = Role.responder;
	const status = Status.accepted;

	const DHs = senderKeyPair;
	const RK = sk;

	return {
		sessionid: randomUUID(),
		role,
		status,
		DHs,
		RK,
		Ns: 0,
		Nr: 0,
		PN: 0,
		MKSKIPPED: {},
		version: 0,
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
	newPartialState: Partial<ModifiableState>,
) => {
	return {
		...oldState,
		...newPartialState,
		version: oldState.version + 1,
		prev: oldState,
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

	console.log(
		`encrypt - role: ${newState.role}, mk: ${mk.toString("hex")}, CKs: ${newCKs.toString("hex")}`,
	);
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
	let newState = state;

	const plaintext = TrySkippedMessageKeys(newState, header, ciphertext, ad);
	if (plaintext !== null) {
		return [newState, plaintext];
	}

	if (header.dh !== newState.DHr) {
		newState = SkipMessageKeys(newState, header.pn);
		newState = DHRatchet(newState, header);
	}

	newState = SkipMessageKeys(newState, header.n);

	const oldCKr = newState.CKr;
	const [CKr, mk] = KDF_CK(newState.CKr);
	const Nr = newState.Nr + 1;

	newState = RotateState(newState, {
		CKr,
		Nr,
	});

	console.log(
		`decrypt - role: ${newState.role}, mk: ${mk.toString("hex")}, oldCKr: ${oldCKr?.toString("hex")}, CKr: ${CKr.toString("hex")}`,
	);
	return [newState, DECRYPT(mk, ciphertext, CONCAT(ad, header))];
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

	let newState = state;
	if (newState.CKr !== null) {
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
	}

	return newState;
};

const DHRatchet = (state: State, header: Header): State => {
	const PN = state.Ns;
	const Ns = 0;
	const Nr = 0;
	const DHr = header.dh;
	const [RK1, CKr] = KDF_RK(state.RK, DH(state.DHs, DHr));
	const DHs = GENERATE_DH();
	const [RK2, CKs] = KDF_RK(RK1, DH(DHs, DHr));

	const newState = RotateState(state, {
		DHs,
		DHr,
		RK: RK2,
		CKs,
		CKr,
		Ns,
		Nr,
		PN,
	});

	console.log(` --- ratchet ---
 - old state: ${StateToString(state)}
 - new state: ${StateToString(newState)}`);

	return newState;
};

export const StateToString = (state: State): string => {
	const dump = Object.entries(state).reduce((accu, [key, val]) => {
		switch (key) {
			case "DHs":
				return {
					// biome-ignore lint/performance/noAccumulatingSpread: temporary solution
					...accu,
					[key]: {
						publicKey: val.publicKey.toString("hex"),
						privateKey: val.privateKey.toString("hex"),
					},
				};
			case "RK":
			case "CKs":
			case "CKr":
				return {
					// biome-ignore lint/performance/noAccumulatingSpread: temporary solution
					...accu,
					[key]: val.toString("hex"),
				};
			case "prev":
				return {
					// biome-ignore lint/performance/noAccumulatingSpread: temporary solution
					...accu,
					[key]: val != null,
				};
			default:
				return {
					// biome-ignore lint/performance/noAccumulatingSpread: temporary solution
					...accu,
					[key]: val,
				};
		}
	}, {});
	return JSON.stringify(dump);
};
