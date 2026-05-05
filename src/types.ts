export type UserProfile = {
  id: string;
  username: string;
  display_name: string;
  public_key: string;
  wrapped_private_key: string;
  pbkdf2_salt: string;
  created_at: string;
};

export type AuthResponse = {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
  user: UserProfile;
};

export type SearchUser = {
  id: string;
  username: string;
  display_name: string;
};

export type Conversation = SearchUser & {
  user_id: string;
  last_message_at: string;
};

export type EncryptedPayload = {
  ciphertext: string;
  iv: string;
  encryptedKey: string;
  encryptedKeyForSelf: string;
};

export type MessageRecord = {
  id: string;
  from_user_id: string;
  to_user_id: string;
  payload: EncryptedPayload;
  delivered?: boolean;
  created_at: string;
};

export type ChatMessage = MessageRecord & {
  plaintext?: string;
  decryptError?: string;
  replayWarning?: string;
  pending?: boolean;
};

export type SessionTokens = {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
};

export type CryptoSession = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
};
