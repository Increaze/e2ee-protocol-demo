import type { EncryptedPayload } from "./types";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const wrappedPrivateKeyMagic = new Uint8Array([0x57, 0x42, 0x50, 0x31]);
const pbkdf2Iterations = 210_000;
const legacyPbkdf2Iterations = 310_000;

const rsaAlgorithm: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

export async function generateIdentityKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(rsaAlgorithm, true, ["encrypt", "decrypt"]);
}

export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveWrappingKey(
  password: string,
  salt: ArrayBuffer,
  iterations = pbkdf2Iterations,
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("spki", publicKey);
  return arrayBufferToBase64(exported);
}

export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    base64ToArrayBuffer(publicKeyBase64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
}

export async function publicKeyFingerprint(publicKeyBase64: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    base64ToArrayBuffer(publicKeyBase64),
  );
  const hex = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return hex
    .slice(0, 32)
    .match(/.{1,4}/g)!
    .join(" ");
}

export async function wrapPrivateKey(
  privateKey: CryptoKey,
  wrappingKey: CryptoKey,
): Promise<string> {
  const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8", privateKey);
  const payloadKey = await importPrivateKeyPayloadKey(
    packagePrivateKey(exportedPrivateKey),
  );
  const wrapped = await crypto.subtle.wrapKey("raw", payloadKey, wrappingKey, {
    name: "AES-KW",
  });
  return arrayBufferToBase64(wrapped);
}

export async function unwrapPrivateKey(
  wrappedPrivateKey: string,
  wrappingKey: CryptoKey,
): Promise<CryptoKey> {
  const wrappedPrivateKeyBytes = base64ToArrayBuffer(wrappedPrivateKey);

  try {
    const payloadKey = await crypto.subtle.unwrapKey(
      "raw",
      wrappedPrivateKeyBytes,
      wrappingKey,
      { name: "AES-KW" },
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const packagedPrivateKey = await crypto.subtle.exportKey("raw", payloadKey);
    const privateKeyPkcs8 = unpackagePrivateKey(packagedPrivateKey);
    return importPrivateKey(privateKeyPkcs8);
  } catch {
    return crypto.subtle.unwrapKey(
      "pkcs8",
      wrappedPrivateKeyBytes,
      wrappingKey,
      { name: "AES-KW" },
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"],
    );
  }
}

async function importPrivateKey(privateKeyPkcs8: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    privateKeyPkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"],
  );
}

async function importPrivateKeyPayloadKey(payload: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    payload,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
}

function packagePrivateKey(privateKeyPkcs8: ArrayBuffer): ArrayBuffer {
  const privateKeyBytes = new Uint8Array(privateKeyPkcs8);
  const headerLength = 8;
  const unpaddedLength = headerLength + privateKeyBytes.byteLength;
  const paddingLength = (8 - (unpaddedLength % 8)) % 8;
  const packaged = new Uint8Array(unpaddedLength + paddingLength);
  const view = new DataView(packaged.buffer);

  packaged.set(wrappedPrivateKeyMagic, 0);
  view.setUint32(4, privateKeyBytes.byteLength, false);
  packaged.set(privateKeyBytes, headerLength);

  return packaged.buffer;
}

function unpackagePrivateKey(packagedPrivateKey: ArrayBuffer): ArrayBuffer {
  const packagedBytes = new Uint8Array(packagedPrivateKey);
  const view = new DataView(packagedPrivateKey);

  for (let index = 0; index < wrappedPrivateKeyMagic.byteLength; index += 1) {
    if (packagedBytes[index] !== wrappedPrivateKeyMagic[index]) {
      throw new Error("Unsupported wrapped private key format");
    }
  }

  const privateKeyLength = view.getUint32(4, false);
  const privateKeyStart = 8;
  const privateKeyEnd = privateKeyStart + privateKeyLength;

  if (privateKeyEnd > packagedBytes.byteLength) {
    throw new Error("Wrapped private key package is truncated");
  }

  return packagedBytes.slice(privateKeyStart, privateKeyEnd).buffer;
}

export async function createRegistrationKeys(password: string) {
  const keyPair = await generateIdentityKeyPair();
  const salt = generateSalt();
  const wrappingKey = await deriveWrappingKey(password, salt.buffer);
  const [publicKey, wrappedPrivateKey] = await Promise.all([
    exportPublicKey(keyPair.publicKey),
    wrapPrivateKey(keyPair.privateKey, wrappingKey),
  ]);

  return {
    publicKey,
    wrappedPrivateKey,
    pbkdf2Salt: arrayBufferToBase64(salt.buffer),
    cryptoSession: {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    },
  };
}

export async function restorePrivateKey(
  password: string,
  wrappedPrivateKey: string,
  pbkdf2Salt: string,
): Promise<CryptoKey> {
  const salt = base64ToArrayBuffer(pbkdf2Salt);

  try {
    const wrappingKey = await deriveWrappingKey(password, salt);
    return await unwrapPrivateKey(wrappedPrivateKey, wrappingKey);
  } catch {
    const legacyWrappingKey = await deriveWrappingKey(
      password,
      salt,
      legacyPbkdf2Iterations,
    );
    return unwrapPrivateKey(wrappedPrivateKey, legacyWrappingKey);
  }
}

export async function encryptMessageForRecipient(
  plaintext: string,
  recipientPublicKey: CryptoKey,
  senderPublicKey: CryptoKey,
): Promise<EncryptedPayload> {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedPlaintext = textEncoder.encode(plaintext);
  const [ciphertext, rawAesKey] = await Promise.all([
    crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encodedPlaintext),
    crypto.subtle.exportKey("raw", aesKey),
  ]);

  const [encryptedKey, encryptedKeyForSelf] = await Promise.all([
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPublicKey, rawAesKey),
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, senderPublicKey, rawAesKey),
  ]);

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
    encryptedKey: arrayBufferToBase64(encryptedKey),
    encryptedKeyForSelf: arrayBufferToBase64(encryptedKeyForSelf),
  };
}

export async function decryptMessagePayload(
  payload: EncryptedPayload,
  privateKey: CryptoKey,
  ownMessage: boolean,
): Promise<string> {
  const encryptedKey = ownMessage ? payload.encryptedKeyForSelf : payload.encryptedKey;
  const rawAesKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64ToArrayBuffer(encryptedKey),
  );
  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToArrayBuffer(payload.iv) },
    aesKey,
    base64ToArrayBuffer(payload.ciphertext),
  );

  return textDecoder.decode(plaintext);
}
