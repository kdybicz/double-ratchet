import { randomUUID } from "node:crypto";

import { GENERATE_DH } from "../utils";
import {
	InitInitiatorState,
	InitResponderState,
	RatchetDecrypt,
	RatchetEncrypt,
	Role,
	type State,
	StateToString,
	Status,
} from "./ratchet";
import type { Server } from "./server";
import { DH, Encode, KDF, Sig, SigVer } from "./utils";

export type PrekeyBundle = {
	identityKey: string;
	prekey: DHPublicKeyRecord;
	signature: string;
	oneTimePrekey: DHPublicKeyRecord | undefined;
};

export type DHKeyPair = {
	id: string;
	// Secret Key / Private Key
	sk: Buffer<ArrayBufferLike>;
	// Public Key
	pk: Buffer<ArrayBufferLike>;
};

export type DHPublicKeyRecord = {
	id: string;
	// Public Key
	pk: string;
};

export type PrekeyPublicRecord = {
	identityKey: DHPublicKeyRecord;
	prekey: DHPublicKeyRecord;
	signature: string;
	oneTimePrekeys: DHPublicKeyRecord[];
	createdAt: Date;
};

export type Prekey = {
	prekey: DHKeyPair;
	signature: string;
	oneTimePrekeys: Record<string, DHKeyPair>;
	createdAt: Date;
};

export type SecretMessage = {
	// Sender id
	sid: string;
	// Sender Identity Public Key
	ik?: string;
	// Sender Ephemeral Public Key
	ek?: string;
	// Recipient Prekey Id
	pkid?: string;
	// Recipient One Time Prekey Id
	opkid?: string;
	// Encrypted header and message separated with ;
	msg: string;
};

export type Recipient = {
	id: string;
	state: State;
};

export class Client {
	protected server: Server;

	protected userId: string;
	protected identityKey: DHKeyPair;
	protected prekeys: Prekey[] = [];
	protected recipients: Record<string, Recipient> = {};

	constructor(server: Server, userId: string) {
		this.server = server;

		this.userId = userId;
		this.identityKey = this.generateDiffieHellmanKeyPair();

		this.rotatePrekey();
	}

	protected generateDiffieHellmanKeyPair(): DHKeyPair {
		const id = randomUUID();
		const keyPair = GENERATE_DH();

		return {
			id: id,
			sk: keyPair.privateKey,
			pk: keyPair.publicKey,
		};
	}

	protected generateOneTimePrekeys(size = 10): Record<string, DHKeyPair> {
		const prekeys: Record<string, DHKeyPair> = {};

		while (Object.keys(prekeys).length < size) {
			const keyPair = this.generateDiffieHellmanKeyPair();
			if (keyPair.id in Object.keys(prekeys)) {
				continue;
			}

			prekeys[keyPair.id] = keyPair;
		}

		return prekeys;
	}

	private static convertKeyPairToPublicKeyRecord(
		keyPair: DHKeyPair,
	): DHPublicKeyRecord {
		return {
			id: keyPair.id,
			pk: keyPair.pk.toString("hex"),
		};
	}

	protected rotatePrekey() {
		const prekey = this.generateDiffieHellmanKeyPair();
		const signature = Sig(prekey.sk, this.identityKey.pk);
		const oneTimePrekeys: Record<string, DHKeyPair> =
			this.generateOneTimePrekeys();

		const newPrekey: Prekey = {
			prekey,
			signature,
			oneTimePrekeys,
			createdAt: new Date(),
		};

		const bundle: PrekeyPublicRecord = {
			identityKey: Client.convertKeyPairToPublicKeyRecord(this.identityKey),
			prekey: Client.convertKeyPairToPublicKeyRecord(newPrekey.prekey),
			signature: newPrekey.signature,
			oneTimePrekeys: Object.values(newPrekey.oneTimePrekeys).map(
				Client.convertKeyPairToPublicKeyRecord,
			),
			createdAt: newPrekey.createdAt,
		};

		this.server.registerUser({
			userId: this.userId,
			prekey: bundle,
		});

		this.prekeys.unshift(newPrekey);
	}

	/**
	 * https://www.cs.ru.nl/bachelors-theses/2021/Ferran_van_der_Have___4104145___The_X3DH_Protocol_-_A_Proof_of_Security.pdf
	 *
	 * @param userId
	 * @param message
	 * @returns
	 */
	public sendMessage(userId: string, message: string) {
		const bundle = this.server.fetchPrekeyBundle(userId);

		const state = this.recipients[userId]?.state;
		if (state == null) {
			const prekey = Buffer.from(bundle.prekey.pk, "hex");

			const validSig = SigVer(
				prekey,
				Buffer.from(bundle.identityKey, "hex"),
				bundle.signature,
			);
			if (!validSig) {
				console.error(
					`Prekey bundle signature verification failed for user: ${userId}`,
				);
				return;
			}

			const IKa = this.identityKey.sk;
			const EKa = GENERATE_DH();
			const IKb = Buffer.from(bundle.identityKey, "hex");
			const SPKb = prekey;
			const OPKb =
				bundle.oneTimePrekey != null
					? Buffer.from(bundle.oneTimePrekey.pk, "hex")
					: null;

			const DHList: Buffer<ArrayBufferLike>[] = [];

			const DH1 = DH(IKa, SPKb);
			DHList.push(DH1);

			const DH2 = DH(EKa.privateKey, IKb);
			DHList.push(DH2);

			const DH3 = DH(EKa.privateKey, SPKb);
			DHList.push(DH3);
			if (OPKb != null) {
				const DH4 = DH(EKa.privateKey, OPKb);
				DHList.push(DH4);
			}

			const SK = KDF(Buffer.concat(DHList));
			const AD = Buffer.concat([Encode(this.identityKey.pk), Encode(IKb)]);

			// console.log(
			// 	JSON.stringify({
			// 		sk: SK.toString("hex"),
			// 		ad: AD.toString("hex"),
			// 	}),
			// );

			const initialState = InitInitiatorState(
				SK,
				{ publicKey: this.identityKey.pk, privateKey: this.identityKey.sk },
				bundle.identityKey,
			);
			const [newState, header, encryptedMessage] = RatchetEncrypt(
				initialState,
				message,
				AD,
			);

			const secretMessage: SecretMessage = {
				sid: this.userId,
				ik: this.identityKey.pk.toString("hex"),
				ek: EKa.publicKey.toString("hex"),
				pkid: bundle.prekey.id,
				opkid: bundle.oneTimePrekey?.id,
				msg: `${JSON.stringify(header)};${encryptedMessage}`,
			};

			console.log(`-- ${this.userId}
 - state before send: ${StateToString(initialState)}
 - sends initial message to ${userId} - Header: ${JSON.stringify(header)} Encrypted message: ${encryptedMessage}
 - current state: ${StateToString(newState)}
`);

			this.server.sendMessage(userId, secretMessage);

			this.recipients[userId] = {
				id: userId,
				state: newState,
			};
		} else {
			const AD = Buffer.concat([
				Encode(this.identityKey.pk),
				Encode(Buffer.from(bundle.identityKey, "hex")),
			]);
			const [newState, header, encryptedMessage] = RatchetEncrypt(
				state,
				message,
				AD,
			);

			const secretMessage: SecretMessage = {
				sid: this.userId,
				msg: `${JSON.stringify(header)};${encryptedMessage}`,
			};

			console.log(`-- ${this.userId}
 - state before send: ${StateToString(state)}
 - sends message to ${userId} - Header: ${JSON.stringify(header)} Encrypted message: ${encryptedMessage}
 - current state: ${StateToString(newState)}
`);

			this.server.sendMessage(userId, secretMessage);

			this.recipients[userId] = {
				id: userId,
				state: newState,
			};
		}
	}

	protected decryptMessage(message: SecretMessage): string | null {
		const recipientId = message.sid;
		const bundle = this.server.fetchPrekeyBundle(recipientId);

		let state = this.recipients[recipientId]?.state;
		if (state == null) {
			const prekey = Buffer.from(bundle.prekey.pk, "hex");

			const validSig = SigVer(
				prekey,
				Buffer.from(bundle.identityKey, "hex"),
				bundle.signature,
			);
			if (!validSig) {
				return null;
			}

			const IKa = Buffer.from(message.ik as string, "hex");
			const EKa = Buffer.from(message.ek as string, "hex");
			const IKb = this.identityKey.sk;
			const SPKb = this.prekeys.find((val) => val.prekey.id === message.pkid)
				?.prekey.sk;
			if (SPKb == null) {
				throw new Error(`Prekey with given ID was not found: ${message.pkid}`);
			}
			const OPKb =
				message.opkid != null
					? this.prekeys.find((val) => val.prekey.id === message.pkid)
							?.oneTimePrekeys?.[message.opkid]?.sk
					: null;

			const DHList: Buffer<ArrayBufferLike>[] = [];

			const DH1 = DH(SPKb, IKa);
			DHList.push(DH1);

			const DH2 = DH(IKb, EKa);
			DHList.push(DH2);

			const DH3 = DH(SPKb, EKa);
			DHList.push(DH3);
			if (OPKb != null) {
				const DH4 = DH(OPKb, EKa);
				DHList.push(DH4);
			}

			const SK = KDF(Buffer.concat(DHList));
			const AD = Buffer.concat([Encode(IKa), Encode(this.identityKey.pk)]);

			// console.log(
			// 	JSON.stringify({
			// 		sk: SK.toString("hex"),
			// 		ad: AD.toString("hex"),
			// 	}),
			// );

			state = InitResponderState(SK, {
				publicKey: this.identityKey.pk,
				privateKey: this.identityKey.sk,
			});

			const [header, encryptedMessage] = message.msg.split(";");
			const [newState, decryptedMessage] = RatchetDecrypt(
				state,
				JSON.parse(header),
				encryptedMessage,
				AD,
			);

			console.log(`-- ${this.userId}
 - state before receive: ${StateToString(state)}
 - receives initial message from ${recipientId} - Header: ${header} Decrypted message: ${decryptedMessage}
 - current state: ${StateToString(newState)}
`);

			// Remove used One Time Prekey
			const oneTimePrekeys = this.prekeys.find(
				(val) => val.prekey.id === message.pkid,
			)?.oneTimePrekeys;
			if (oneTimePrekeys != null && message.opkid != null) {
				delete oneTimePrekeys[message.opkid];
			}

			this.recipients[recipientId] = {
				id: recipientId,
				state: newState,
			};

			return decryptedMessage;
		}

		const AD = Buffer.concat([
			Encode(Buffer.from(bundle.identityKey, "hex")),
			Encode(this.identityKey.pk),
		]);
		console.log(`-- ${this.userId}
 - state before receive: ${StateToString(state)}`);
		const [header, encryptedMessage] = message.msg.split(";");
		console.log(` - receives message from ${recipientId} - Header: ${header}`);
		const [newState, decryptedMessage] = RatchetDecrypt(
			state,
			JSON.parse(header),
			encryptedMessage,
			AD,
		);

		console.log(` - receives message from ${recipientId} - Decrypted message: ${decryptedMessage}
 - current state: ${StateToString(newState)}
`);

		this.recipients[recipientId] = {
			id: recipientId,
			state: newState,
		};

		return decryptedMessage;
	}

	public fetchMessages() {
		const messages = this.server
			.fetchMessages(this.userId)
			.map(this.decryptMessage.bind(this));
		return messages;
	}
}
