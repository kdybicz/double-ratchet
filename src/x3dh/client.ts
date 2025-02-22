import { randomUUID } from "node:crypto";

import { GENERATE_DH } from "../utils";
import {
	InitState,
	RatchetDecrypt,
	RatchetEncrypt,
	type State,
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
	ik: string;
	ek: string;
	pkid: string;
	opkid?: string;
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
		const signature = Sig(
			prekey.sk as Buffer,
			Buffer.from(`${this.userId} and soe other important info`),
		).toString("hex");
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

	public sendMessage(userId: string, message: string) {
		const recipient = this.recipients[userId];
		if (recipient == null) {
			const bundle = this.server.fetchPrekeyBundle(userId);
			const prekey = Buffer.from(bundle.prekey.pk, "hex");

			const validSig = SigVer(prekey, Buffer.from(bundle.signature, "hex"));
			if (!validSig) {
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

			console.log(
				JSON.stringify({
					sk: SK.toString("hex"),
					ad: AD.toString("hex"),
				}),
			);

			const initialState = InitState(
				SK,
				{ publicKey: this.identityKey.pk, privateKey: this.identityKey.sk },
				bundle.identityKey,
			);
			const [state, header, encryptedMessage] = RatchetEncrypt(
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
			console.log(`Secret message: ${JSON.stringify(secretMessage)}`);
			console.log(`State: ${JSON.stringify(state)}`);

			this.server.sendMessage(userId, secretMessage);

			this.recipients[userId] = {
				id: userId,
				state,
			};
		}
	}

	protected decryptMessage(message: SecretMessage): string | null {
		const recipientId = message.sid;

		const recipient = this.recipients[recipientId];
		if (recipient == null) {
			const bundle = this.server.fetchPrekeyBundle(recipientId);

			const prekey = Buffer.from(bundle.prekey.pk, "hex");

			const validSig = SigVer(prekey, Buffer.from(bundle.signature, "hex"));
			if (!validSig) {
				return null;
			}

			const IKa = Buffer.from(message.ik, "hex");
			const EKa = Buffer.from(message.ek, "hex");
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

			console.log(
				JSON.stringify({
					sk: SK.toString("hex"),
					ad: AD.toString("hex"),
				}),
			);

			const initialState = InitState(
				SK,
				{ publicKey: this.identityKey.pk, privateKey: this.identityKey.sk },
				message.ik,
			);

			const [header, encryptedMessage] = message.msg.split(";");
			const [state, decryptedMessage] = RatchetDecrypt(
				initialState,
				JSON.parse(header),
				encryptedMessage,
				AD,
			);

			console.log(`Decrypted message: ${decryptedMessage}`);
			console.log(`State: ${JSON.stringify(state)}`);

			// Remove used One Time Prekey
			const oneTimePrekeys = this.prekeys.find(
				(val) => val.prekey.id === message.pkid,
			)?.oneTimePrekeys;
			if (oneTimePrekeys != null && message.opkid != null) {
				delete oneTimePrekeys[message.opkid];
			}

			this.recipients[recipientId] = {
				id: recipientId,
				state,
			};

			return decryptedMessage;
		}

		return null;
	}

	public fetchMessages() {
		const messages = this.server
			.fetchMessages(this.userId)
			.map(this.decryptMessage.bind(this));
		return messages;
	}
}
