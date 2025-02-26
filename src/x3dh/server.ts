import type { PrekeyBundle, PrekeyPublicRecord, SecretMessage } from "./client";

type UserRegister = {
	userId: string;
	prekey: PrekeyPublicRecord;
};

export class Server {
	protected users: Record<string, PrekeyPublicRecord>;
	protected messages: Record<string, SecretMessage[]>;

	constructor() {
		this.users = {};
		this.messages = {};
	}

	public registerUser = (data: UserRegister) => {
		this.users[data.userId] = data.prekey;
	};

	public fetchPrekeyBundle = (userId: string) => {
		const record = this.users[userId];

		const bundle: PrekeyBundle = {
			identityKey: record.identityKey.pk,
			prekey: record.prekey,
			signature: record.signature,
			oneTimePrekey: record.oneTimePrekeys.shift(),
		};

		return bundle;
	};

	public sendMessage(userId: string, message: SecretMessage): void {
		const userMessages = this.messages[userId] ?? [];
		userMessages.push(message);
		this.messages[userId] = userMessages;
	}

	public fetchMessages(userId: string): SecretMessage[] {
		const messages = this.messages[userId] ?? [];
		delete this.messages[userId]
		return messages;
	}
}
