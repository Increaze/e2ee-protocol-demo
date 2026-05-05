import type { SessionTokens, UserProfile } from "./types";

const DB_NAME = "whisperbox-client";
const DB_VERSION = 1;
const STORE_NAME = "session";
const TOKENS_KEY = "tokens";
const PROFILE_KEY = "profile";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function writeValue<T>(key: string, value: T): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function readValue<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  const value = await new Promise<T | undefined>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const request = tx.objectStore(STORE_NAME).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return value;
}

async function deleteValue(key: string): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

export async function saveSession(
  tokens: SessionTokens,
  profile: UserProfile,
): Promise<void> {
  await Promise.all([
    writeValue(TOKENS_KEY, tokens),
    writeValue(PROFILE_KEY, profile),
  ]);
}

export async function loadStoredSession(): Promise<{
  tokens?: SessionTokens;
  profile?: UserProfile;
}> {
  const [tokens, profile] = await Promise.all([
    readValue<SessionTokens>(TOKENS_KEY),
    readValue<UserProfile>(PROFILE_KEY),
  ]);
  return { tokens, profile };
}

export async function clearStoredSession(): Promise<void> {
  await Promise.all([deleteValue(TOKENS_KEY), deleteValue(PROFILE_KEY)]);
}
