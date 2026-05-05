import type {
  AuthResponse,
  Conversation,
  EncryptedPayload,
  MessageRecord,
  SearchUser,
  UserProfile,
} from "./types";

const API_BASE = "https://whisperbox.koyeb.app";

type RequestOptions = {
  token?: string;
  method?: string;
  body?: unknown;
};

async function apiRequest<T>(
  path: string,
  { token, method = "GET", body }: RequestOptions = {},
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const detail = await response
      .json()
      .then((data) => data.detail ?? JSON.stringify(data))
      .catch(() => response.statusText);
    throw new Error(typeof detail === "string" ? detail : "Request failed");
  }

  return response.json() as Promise<T>;
}

export const api = {
  register(input: {
    username: string;
    display_name: string;
    password: string;
    public_key: string;
    wrapped_private_key: string;
    pbkdf2_salt: string;
  }) {
    return apiRequest<AuthResponse>("/auth/register", {
      method: "POST",
      body: input,
    });
  },

  login(input: { username: string; password: string }) {
    return apiRequest<AuthResponse>("/auth/login", {
      method: "POST",
      body: input,
    });
  },

  me(token: string) {
    return apiRequest<UserProfile>("/auth/me", { token });
  },

  refresh(refresh_token: string) {
    return apiRequest<{ access_token: string; token_type: "bearer"; expires_in: number }>(
      "/auth/refresh",
      { method: "POST", body: { refresh_token } },
    );
  },

  logout(token: string, refresh_token: string) {
    return apiRequest<{ detail: string }>("/auth/logout", {
      token,
      method: "POST",
      body: { refresh_token },
    });
  },

  searchUsers(token: string, query: string) {
    return apiRequest<SearchUser[]>(
      `/users/search?q=${encodeURIComponent(query)}`,
      { token },
    );
  },

  getPublicKey(token: string, userId: string) {
    return apiRequest<{ public_key: string }>(`/users/${userId}/public-key`, {
      token,
    });
  },

  getConversations(token: string) {
    return apiRequest<Conversation[]>("/conversations", { token });
  },

  getMessages(token: string, userId: string, limit = 50) {
    return apiRequest<MessageRecord[]>(
      `/conversations/${userId}/messages?limit=${limit}`,
      { token },
    );
  },

  sendMessage(token: string, to: string, payload: EncryptedPayload) {
    return apiRequest<MessageRecord>("/messages", {
      token,
      method: "POST",
      body: { to, payload },
    });
  },
};

export function createMessageSocket(token: string): WebSocket {
  return new WebSocket(`wss://whisperbox.koyeb.app/ws?token=${encodeURIComponent(token)}`);
}
