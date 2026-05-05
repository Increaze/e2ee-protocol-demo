import {
  AlertTriangle,
  Check,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  MessageCircle,
  Search,
  Send,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, createMessageSocket } from "./api";
import {
  createRegistrationKeys,
  decryptMessagePayload,
  encryptMessageForRecipient,
  importPublicKey,
  publicKeyFingerprint,
  restorePrivateKey,
} from "./crypto";
import { clearStoredSession, loadStoredSession, saveSession } from "./storage";
import type {
  AuthResponse,
  ChatMessage,
  Conversation,
  CryptoSession,
  MessageRecord,
  SearchUser,
  SessionTokens,
  UserProfile,
} from "./types";

type AuthMode = "login" | "register";
type SocketState = "disconnected" | "connecting" | "connected";

const tokenExpiryBufferMs = 45_000;
const replayWindowMs = 1000 * 60 * 60 * 24 * 30;

type PlaintextEnvelope = {
  version: 1;
  messageId: string;
  sentAt: string;
  body: string;
};

function authToTokens(auth: AuthResponse): SessionTokens {
  return {
    accessToken: auth.access_token,
    refreshToken: auth.refresh_token,
    expiresAt: Date.now() + auth.expires_in * 1000,
  };
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
    month: "short",
    day: "numeric",
  }).format(new Date(value));
}

function userFromConversation(conversation: Conversation): SearchUser {
  return {
    id: conversation.user_id,
    username: conversation.username,
    display_name: conversation.display_name,
  };
}

function getPasswordStrength(password: string) {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  if (!password) {
    return { label: "", className: "", score: 0, hint: "" };
  }
  if (score <= 2) {
    return {
      label: "Weak",
      className: "weak",
      score,
      hint: "Use 12+ characters with mixed letters, numbers, or symbols.",
    };
  }
  if (score <= 4) {
    return {
      label: "Good",
      className: "good",
      score,
      hint: "A longer passphrase makes your private key harder to unlock.",
    };
  }
  return {
    label: "Strong",
    className: "strong",
    score,
    hint: "Strong password for protecting your wrapped private key.",
  };
}

function createPlaintextEnvelope(body: string): PlaintextEnvelope {
  return {
    version: 1,
    messageId: crypto.randomUUID(),
    sentAt: new Date().toISOString(),
    body,
  };
}

function parsePlaintextEnvelope(plaintext: string): PlaintextEnvelope {
  try {
    const parsed = JSON.parse(plaintext) as Partial<PlaintextEnvelope>;
    if (
      parsed.version === 1 &&
      typeof parsed.messageId === "string" &&
      typeof parsed.sentAt === "string" &&
      typeof parsed.body === "string"
    ) {
      return parsed as PlaintextEnvelope;
    }
  } catch {
    // Older messages encrypted only the body string.
  }

  return {
    version: 1,
    messageId: `legacy:${plaintext}`,
    sentAt: new Date().toISOString(),
    body: plaintext,
  };
}

function displayPlaintext(plaintext?: string): string | undefined {
  if (!plaintext) {
    return plaintext;
  }

  return parsePlaintextEnvelope(plaintext).body;
}

function replayWarningForEnvelope(
  envelope: PlaintextEnvelope,
  seenMessageIds: Set<string>,
): string | undefined {
  if (seenMessageIds.has(envelope.messageId)) {
    return "Possible replay detected: this encrypted message ID was already seen.";
  }

  const sentAt = new Date(envelope.sentAt).getTime();
  if (!Number.isFinite(sentAt)) {
    return "Message timestamp could not be verified.";
  }

  if (Math.abs(Date.now() - sentAt) > replayWindowMs) {
    return "Message timestamp is outside the expected replay window.";
  }

  return undefined;
}

export default function App() {
  const [authMode, setAuthMode] = useState<AuthMode>("register");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [authStatus, setAuthStatus] = useState("");
  const [unlockPassword, setUnlockPassword] = useState("");
  const [showUnlockPassword, setShowUnlockPassword] = useState(false);
  const [authError, setAuthError] = useState("");

  const [tokens, setTokens] = useState<SessionTokens | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [cryptoSession, setCryptoSession] = useState<CryptoSession | null>(null);
  const [restoreProfile, setRestoreProfile] = useState<UserProfile | null>(null);
  const [restoreTokens, setRestoreTokens] = useState<SessionTokens | null>(null);
  const [booting, setBooting] = useState(true);

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedUser, setSelectedUser] = useState<SearchUser | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [unreadThreads, setUnreadThreads] = useState<Record<string, boolean>>({});
  const [ownFingerprint, setOwnFingerprint] = useState("");
  const [recipientFingerprint, setRecipientFingerprint] = useState("");
  const [securityDetailsOpen, setSecurityDetailsOpen] = useState(false);
  const [messageText, setMessageText] = useState("");
  const [threadBusy, setThreadBusy] = useState(false);
  const [sendBusy, setSendBusy] = useState(false);
  const [chatError, setChatError] = useState("");

  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchUser[]>([]);
  const [searchBusy, setSearchBusy] = useState(false);

  const [socketState, setSocketState] = useState<SocketState>("disconnected");
  const [onlineUsers, setOnlineUsers] = useState<Set<string>>(new Set());
  const socketRef = useRef<WebSocket | null>(null);
  const selectedUserRef = useRef<SearchUser | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const seenMessageIdsRef = useRef<Set<string>>(new Set());

  const passwordStrength = useMemo(
    () => getPasswordStrength(password),
    [password],
  );

  useEffect(() => {
    selectedUserRef.current = selectedUser;
  }, [selectedUser]);

  const refreshAccessToken = useCallback(async () => {
    if (!tokens) {
      throw new Error("No active session");
    }
    if (Date.now() < tokens.expiresAt - tokenExpiryBufferMs) {
      return tokens.accessToken;
    }
    const refreshed = await api.refresh(tokens.refreshToken);
    const nextTokens = {
      ...tokens,
      accessToken: refreshed.access_token,
      expiresAt: Date.now() + refreshed.expires_in * 1000,
    };
    setTokens(nextTokens);
    if (profile) {
      await saveSession(nextTokens, profile);
    }
    return nextTokens.accessToken;
  }, [profile, tokens]);

  const decryptRecords = useCallback(
    async (records: MessageRecord[]) => {
      if (!cryptoSession || !profile) {
        return [];
      }
      const decrypted = await Promise.all(
        records.map(async (message) => {
          try {
            const ownMessage = message.from_user_id === profile.id;
            const decryptedPlaintext = await decryptMessagePayload(
              message.payload,
              cryptoSession.privateKey,
              ownMessage,
            );
            const envelope = parsePlaintextEnvelope(decryptedPlaintext);
            const replayWarning = replayWarningForEnvelope(
              envelope,
              seenMessageIdsRef.current,
            );

            seenMessageIdsRef.current.add(envelope.messageId);
            return { ...message, plaintext: envelope.body, replayWarning };
          } catch {
            return {
              ...message,
              decryptError: "Could not decrypt this message on this device.",
            };
          }
        }),
      );
      return decrypted.sort(
        (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
      );
    },
    [cryptoSession, profile],
  );

  const loadConversations = useCallback(async () => {
    if (!tokens) {
      return;
    }
    const token = await refreshAccessToken();
    const data = await api.getConversations(token);
    setConversations(data);
  }, [refreshAccessToken, tokens]);

  const loadMessages = useCallback(
    async (user: SearchUser) => {
      if (!tokens || !cryptoSession) {
        return;
      }
      setThreadBusy(true);
      setChatError("");
      try {
        const token = await refreshAccessToken();
        const records = await api.getMessages(token, user.id);
        setMessages(await decryptRecords(records));
      } catch (error) {
        setChatError(error instanceof Error ? error.message : "Could not load messages");
      } finally {
        setThreadBusy(false);
      }
    },
    [cryptoSession, decryptRecords, refreshAccessToken, tokens],
  );

  useEffect(() => {
    loadStoredSession()
      .then(({ tokens: storedTokens, profile: storedProfile }) => {
        if (storedTokens && storedProfile) {
          setRestoreTokens(storedTokens);
          setRestoreProfile(storedProfile);
        }
      })
      .finally(() => setBooting(false));
  }, []);

  useEffect(() => {
    if (profile && cryptoSession && tokens) {
      loadConversations().catch(() => undefined);
    }
  }, [cryptoSession, loadConversations, profile, tokens]);

  useEffect(() => {
    if (!profile) {
      setOwnFingerprint("");
      return;
    }

    let cancelled = false;
    publicKeyFingerprint(profile.public_key).then((fingerprint) => {
      if (!cancelled) {
        setOwnFingerprint(fingerprint);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [profile]);

  useEffect(() => {
    if (!tokens || !profile || !cryptoSession) {
      return;
    }

    setSocketState("connecting");
    const socket = createMessageSocket(tokens.accessToken);
    socketRef.current = socket;

    socket.onopen = () => setSocketState("connected");
    socket.onclose = () => setSocketState("disconnected");
    socket.onerror = () => setSocketState("disconnected");
    socket.onmessage = async (event) => {
      try {
        const frame = JSON.parse(event.data);
        if (frame.event === "message.receive") {
          const [decrypted] = await decryptRecords([frame]);
          const selected = selectedUserRef.current;
          if (
            selected &&
            (frame.from_user_id === selected.id || frame.to_user_id === selected.id)
          ) {
            setMessages((current) => [...current, decrypted]);
          } else if (frame.from_user_id !== profile.id) {
            setUnreadThreads((current) => ({
              ...current,
              [frame.from_user_id]: true,
            }));
          }
          loadConversations().catch(() => undefined);
        }
        if (frame.event === "user.online") {
          setOnlineUsers((current) => new Set(current).add(frame.user_id));
        }
        if (frame.event === "user.offline") {
          setOnlineUsers((current) => {
            const next = new Set(current);
            next.delete(frame.user_id);
            return next;
          });
        }
        if (frame.event === "error") {
          setChatError(frame.detail ?? "WebSocket error");
        }
      } catch {
        setChatError("Received an unreadable realtime event");
      }
    };

    return () => {
      socket.close();
      socketRef.current = null;
    };
  }, [cryptoSession, decryptRecords, loadConversations, profile, tokens]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!tokens || searchQuery.trim().length < 2) {
      setSearchResults([]);
      setSearchBusy(false);
      return;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(async () => {
      setSearchBusy(true);
      try {
        const token = await refreshAccessToken();
        if (!controller.signal.aborted) {
          setSearchResults(await api.searchUsers(token, searchQuery.trim()));
        }
      } catch {
        if (!controller.signal.aborted) {
          setSearchResults([]);
        }
      } finally {
        if (!controller.signal.aborted) {
          setSearchBusy(false);
        }
      }
    }, 250);

    return () => {
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [refreshAccessToken, searchQuery, tokens]);

  async function completeSignIn(auth: AuthResponse, session: CryptoSession) {
    const nextTokens = authToTokens(auth);
    setTokens(nextTokens);
    setProfile(auth.user);
    setCryptoSession(session);
    setRestoreProfile(null);
    setRestoreTokens(null);
    await saveSession(nextTokens, auth.user);
  }

  async function handleAuth(event: FormEvent) {
    event.preventDefault();
    const normalizedUsername = username.trim().toLowerCase();
    const normalizedDisplayName = displayName.trim();

    setAuthBusy(true);
    setAuthError("");
    setAuthStatus(authMode === "register" ? "Generating encryption keys..." : "Signing in...");
    try {
      if (authMode === "register") {
        const generated = await createRegistrationKeys(password);
        setAuthStatus("Creating account...");
        const response = await api.register({
          username: normalizedUsername,
          display_name: normalizedDisplayName || normalizedUsername,
          password,
          public_key: generated.publicKey,
          wrapped_private_key: generated.wrappedPrivateKey,
          pbkdf2_salt: generated.pbkdf2Salt,
        });
        await completeSignIn(response, generated.cryptoSession);
      } else {
        const response = await api.login({ username: normalizedUsername, password });
        setAuthStatus("Unlocking private key locally...");
        const privateKey = await restorePrivateKey(
          password,
          response.user.wrapped_private_key,
          response.user.pbkdf2_salt,
        );
        const publicKey = await importPublicKey(response.user.public_key);
        await completeSignIn(response, { privateKey, publicKey });
      }
      setPassword("");
      setUsername("");
      setDisplayName("");
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (authMode === "login" && /invalid|credential|password|unauthorized/i.test(message)) {
        setAuthError("No matching account was found. Register first, or check the username and password.");
      } else {
        setAuthError(message || "Authentication failed. Try again.");
      }
    } finally {
      setAuthBusy(false);
      setAuthStatus("");
    }
  }

  async function handleUnlock(event: FormEvent) {
    event.preventDefault();
    if (!restoreProfile || !restoreTokens) {
      return;
    }
    setAuthBusy(true);
    setAuthError("");
    setAuthStatus("Unlocking private key locally...");
    try {
      const freshTokens =
        Date.now() >= restoreTokens.expiresAt - tokenExpiryBufferMs
          ? {
              ...restoreTokens,
              accessToken: (await api.refresh(restoreTokens.refreshToken)).access_token,
              expiresAt: Date.now() + 900_000,
            }
          : restoreTokens;
      const privateKey = await restorePrivateKey(
        unlockPassword,
        restoreProfile.wrapped_private_key,
        restoreProfile.pbkdf2_salt,
      );
      const publicKey = await importPublicKey(restoreProfile.public_key);
      setTokens(freshTokens);
      setProfile(restoreProfile);
      setCryptoSession({ privateKey, publicKey });
      await saveSession(freshTokens, restoreProfile);
      setUnlockPassword("");
      setRestoreProfile(null);
      setRestoreTokens(null);
    } catch {
      setAuthError("Could not unlock the private key. Check your password.");
    } finally {
      setAuthBusy(false);
      setAuthStatus("");
    }
  }

  async function handleLogout() {
    if (tokens) {
      api.logout(tokens.accessToken, tokens.refreshToken).catch(() => undefined);
    }
    socketRef.current?.close();
    setTokens(null);
    setProfile(null);
    setCryptoSession(null);
    setSelectedUser(null);
    setMessages([]);
    seenMessageIdsRef.current.clear();
    setConversations([]);
    setSearchResults([]);
    setUnreadThreads({});
    setRecipientFingerprint("");
    setSecurityDetailsOpen(false);
    setRestoreProfile(null);
    setRestoreTokens(null);
    await clearStoredSession();
  }

  async function handleSelectUser(user: SearchUser) {
    setSelectedUser(user);
    setSearchQuery("");
    setSearchResults([]);
    setRecipientFingerprint("");
    setSecurityDetailsOpen(false);
    setUnreadThreads((current) => {
      if (!current[user.id]) {
        return current;
      }
      const next = { ...current };
      delete next[user.id];
      return next;
    });
    await Promise.all([
      loadMessages(user),
      refreshAccessToken()
        .then((token) => api.getPublicKey(token, user.id))
        .then(({ public_key }) => publicKeyFingerprint(public_key))
        .then(setRecipientFingerprint)
        .catch(() => setRecipientFingerprint("Unavailable")),
    ]);
  }

  async function handleSend(event: FormEvent) {
    event.preventDefault();
    const text = messageText.trim();
    if (!text || !selectedUser || !tokens || !cryptoSession || !profile) {
      return;
    }
    setSendBusy(true);
    setChatError("");
    try {
      const token = await refreshAccessToken();
      const { public_key: recipientPublicKeyBase64 } = await api.getPublicKey(
        token,
        selectedUser.id,
      );
      const recipientPublicKey = await importPublicKey(recipientPublicKeyBase64);
      const envelope = createPlaintextEnvelope(text);
      const payload = await encryptMessageForRecipient(
        JSON.stringify(envelope),
        recipientPublicKey,
        cryptoSession.publicKey,
      );
      seenMessageIdsRef.current.add(envelope.messageId);
      const optimistic: ChatMessage = {
        id: crypto.randomUUID(),
        from_user_id: profile.id,
        to_user_id: selectedUser.id,
        payload,
        plaintext: text,
        created_at: new Date().toISOString(),
        pending: true,
      };
      setMessages((current) => [...current, optimistic]);
      setMessageText("");

      const socket = socketRef.current;
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(
          JSON.stringify({
            event: "message.send",
            to: selectedUser.id,
            payload,
          }),
        );
        setMessages((current) =>
          current.map((message) =>
            message.id === optimistic.id ? { ...message, pending: false } : message,
          ),
        );
      } else {
        const sent = await api.sendMessage(token, selectedUser.id, payload);
        const [decrypted] = await decryptRecords([sent]);
        setMessages((current) =>
          current.map((message) => (message.id === optimistic.id ? decrypted : message)),
        );
      }
      loadConversations().catch(() => undefined);
    } catch (error) {
      setChatError(error instanceof Error ? error.message : "Message failed to send");
    } finally {
      setSendBusy(false);
    }
  }

  const activeConversations = useMemo(() => {
    const users = new Map<string, SearchUser>();
    conversations.forEach((conversation) => {
      users.set(conversation.user_id, userFromConversation(conversation));
    });
    searchResults.forEach((user) => users.set(user.id, user));
    return Array.from(users.values());
  }, [conversations, searchResults]);

  if (booting) {
    return (
      <main className="shell centered">
        <Loader2 className="spin" />
      </main>
    );
  }

  if (restoreProfile && !cryptoSession) {
    return (
      <AuthShell>
        <form className="auth-card" onSubmit={handleUnlock}>
          <div className="brand-mark">
            <KeyRound />
          </div>
          <h1>Unlock WhisperBox</h1>
          <p>
            Signed in as @{restoreProfile.username}. Enter your password to unwrap the
            private key locally.
          </p>
          <label>
            Password
            <div className="password-field">
              <input
                value={unlockPassword}
                onChange={(event) => setUnlockPassword(event.target.value)}
                type={showUnlockPassword ? "text" : "password"}
                autoComplete="current-password"
                minLength={8}
                required
              />
              <button
                type="button"
                onClick={() => setShowUnlockPassword((visible) => !visible)}
                aria-label={showUnlockPassword ? "Hide password" : "Show password"}
                title={showUnlockPassword ? "Hide password" : "Show password"}
              >
                {showUnlockPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </label>
          {authError && <div className="error-banner">{authError}</div>}
          {authStatus && <div className="progress-note">{authStatus}</div>}
          <button className="primary-action" disabled={authBusy}>
            {authBusy ? <Loader2 className="spin" /> : <Lock />}
            Unlock
          </button>
          <button type="button" className="ghost-action" onClick={handleLogout}>
            Use another account
          </button>
        </form>
      </AuthShell>
    );
  }

  if (!profile || !tokens || !cryptoSession) {
    return (
      <AuthShell>
        <form className="auth-card" onSubmit={handleAuth}>
          <div className="brand-mark">
            <ShieldCheck />
          </div>
          <h1>WhisperBox</h1>
          <p>End-to-end encrypted messaging. Keys are made here, not on the server.</p>
          <div className="auth-tabs">
            <button
              type="button"
              className={authMode === "login" ? "active" : ""}
              onClick={() => setAuthMode("login")}
            >
              Sign in
            </button>
            <button
              type="button"
              className={authMode === "register" ? "active" : ""}
              onClick={() => setAuthMode("register")}
            >
              Register
            </button>
          </div>
          <div className="mode-note">
            {authMode === "register"
              ? "New here? Create an encrypted identity first."
              : "Already registered? Sign in with the exact password used at registration."}
          </div>
          <label>
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              pattern="[A-Za-z0-9_-]{3,32}"
              required
            />
          </label>
          {authMode === "register" && (
            <label>
              Display name
              <input
                value={displayName}
                onChange={(event) => setDisplayName(event.target.value)}
                autoComplete="name"
                placeholder="Ada Lovelace"
              />
            </label>
          )}
          <label>
            Password
            <div className="password-field">
              <input
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                type={showPassword ? "text" : "password"}
                autoComplete={authMode === "register" ? "new-password" : "current-password"}
                minLength={8}
                maxLength={128}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword((visible) => !visible)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </label>
          {authMode === "register" && passwordStrength.label && (
            <div className={`password-strength ${passwordStrength.className}`}>
              <div>
                <span>{passwordStrength.label}</span>
                <strong>{passwordStrength.score}/5</strong>
              </div>
              <meter min="0" max="5" value={passwordStrength.score} />
              <p>{passwordStrength.hint}</p>
            </div>
          )}
          {authError && <div className="error-banner">{authError}</div>}
          {authStatus && <div className="progress-note">{authStatus}</div>}
          <button className="primary-action" disabled={authBusy}>
            {authBusy ? <Loader2 className="spin" /> : <Lock />}
            {authMode === "register" ? "Create encrypted identity" : "Open secure inbox"}
          </button>
        </form>
      </AuthShell>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="account-bar">
          <div className="avatar">{initials(profile.display_name || profile.username)}</div>
          <div>
            <strong>{profile.display_name}</strong>
            <span>@{profile.username}</span>
          </div>
          <button className="icon-button" onClick={handleLogout} title="Log out">
            <LogOut size={18} />
          </button>
        </div>
        <div className="status-strip">
          <span className={socketState === "connected" ? "good" : "muted"}>
            {socketState === "connected" ? <Wifi size={16} /> : <WifiOff size={16} />}
            {socketState === "connected" ? "Realtime secure" : "Offline fallback"}
          </span>
          <span>
            <Lock size={16} />
            E2EE
          </span>
        </div>
        <div className="search-box">
          <Search size={18} />
          <input
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Search people"
          />
          {searchBusy && <Loader2 className="spin" size={16} />}
        </div>
        <div className="conversation-list">
          {activeConversations.length === 0 && (
            <div className="empty-list">
              <MessageCircle />
              <span>Search for a user to start a private thread.</span>
            </div>
          )}
          {activeConversations.map((user) => (
            <button
              type="button"
              className={`conversation-item ${selectedUser?.id === user.id ? "active" : ""} ${
                unreadThreads[user.id] ? "unread" : ""
              }`}
              onClick={() => handleSelectUser(user)}
              key={user.id}
            >
              <div className="avatar small">{initials(user.display_name || user.username)}</div>
              <div>
                <strong>{user.display_name}</strong>
                <span>@{user.username}</span>
              </div>
              {unreadThreads[user.id] && (
                <span className="unread-dot" aria-label="Unread messages" />
              )}
              {onlineUsers.has(user.id) && <span className="online-dot" />}
            </button>
          ))}
        </div>
      </aside>

      <section className="chat-panel">
        {selectedUser ? (
          <>
            <header className="chat-header">
              <div className="avatar">{initials(selectedUser.display_name)}</div>
              <div>
                <h2>{selectedUser.display_name}</h2>
                <span>
                  @{selectedUser.username}
                  {onlineUsers.has(selectedUser.id) ? " · online" : ""}
                </span>
              </div>
              <button
                type="button"
                className="cipher-badge"
                onClick={() => setSecurityDetailsOpen((open) => !open)}
                aria-expanded={securityDetailsOpen}
              >
                <ShieldCheck size={17} />
                Client encrypted
              </button>
            </header>

            {securityDetailsOpen && (
              <section className="security-drawer" aria-label="Encryption details">
                <div>
                  <strong>Message encryption</strong>
                  <span>AES-GCM with a fresh 256-bit key and 96-bit IV per message.</span>
                </div>
                <div>
                  <strong>Key exchange</strong>
                  <span>Message keys are encrypted with RSA-OAEP public keys.</span>
                </div>
                <div>
                  <strong>Your public-key fingerprint</strong>
                  <code>{ownFingerprint || "Loading..."}</code>
                </div>
                <div>
                  <strong>{selectedUser.display_name}'s public-key fingerprint</strong>
                  <code>{recipientFingerprint || "Loading..."}</code>
                </div>
                <div>
                  <strong>Private key status</strong>
                  <span>Unlocked locally in memory. The server stores only the wrapped key.</span>
                </div>
              </section>
            )}

            {chatError && (
              <div className="chat-error">
                <AlertTriangle size={18} />
                {chatError}
              </div>
            )}

            <div className="message-scroll">
              {threadBusy ? (
                <div className="thread-loader">
                  <Loader2 className="spin" />
                </div>
              ) : messages.length === 0 ? (
                <div className="empty-thread">
                  <Lock />
                  <strong>No plaintext has crossed the wire.</strong>
                  <span>Send the first encrypted message to this user.</span>
                </div>
              ) : (
                messages.map((message) => {
                  const mine = message.from_user_id === profile.id;
                  return (
                    <article className={`message ${mine ? "mine" : "theirs"}`} key={message.id}>
                      <div className="bubble">
                        {message.decryptError ? (
                          <span className="decrypt-fail">
                            <AlertTriangle size={16} />
                            {message.decryptError}
                          </span>
                        ) : (
                          displayPlaintext(message.plaintext)
                        )}
                      </div>
                      <div className="message-meta">
                        <Lock size={13} />
                        {message.pending ? "Encrypting" : "Encrypted"}
                        <span>{formatTime(message.created_at)}</span>
                      </div>
                      {message.replayWarning && (
                        <div className="replay-warning">
                          <AlertTriangle size={13} />
                          {message.replayWarning}
                        </div>
                      )}
                    </article>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            <form className="composer" onSubmit={handleSend}>
              <div className="composer-input">
                <Lock size={18} />
                <textarea
                  value={messageText}
                  onChange={(event) => setMessageText(event.target.value)}
                  placeholder="Write an encrypted message"
                  rows={1}
                />
              </div>
              <button className="send-button" disabled={sendBusy || !messageText.trim()}>
                {sendBusy ? <Loader2 className="spin" /> : <Send />}
              </button>
            </form>
          </>
        ) : (
          <div className="no-chat">
            <div className="brand-mark">
              <Lock />
            </div>
            <h1>Choose a secure conversation</h1>
            <p>
              Search for a WhisperBox user or pick a previous thread. Messages are
              encrypted before leaving this browser.
            </p>
            <div className="security-checks">
              <span>
                <Check size={16} />
                RSA-OAEP identity keys
              </span>
              <span>
                <Check size={16} />
                AES-GCM message bodies
              </span>
              <span>
                <Check size={16} />
                Wrapped private key storage
              </span>
            </div>
          </div>
        )}
      </section>
    </main>
  );
}

function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <main className="auth-shell">
      <section className="auth-visual">
        <div className="secure-lines">
          <span />
          <span />
          <span />
          <span />
        </div>
        <div className="signal-card">
          <Lock />
          <strong>Server view</strong>
          <code>ciphertext: "d3JhcHBlZC1ibG9i..."</code>
        </div>
      </section>
      {children}
    </main>
  );
}
