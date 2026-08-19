// Which conversation belongs to the site you are looking at.
//
// A chat is tied to a DOMAIN, not a tab or a URL: eBay's sign-in lives on
// signin.ebay.com and its listings on www.ebay.com, and a conversation about
// buying something has to survive the walk between them. Splitting per host
// would have swapped the chat out mid-task — which we watched happen when
// "Save this search" redirected to signin.ebay.com.
//
// Pure and storage-free on purpose. The extension owns localStorage and the
// panel owns the animation; what lives here is the part worth testing without
// either: which chat a domain gets, what a domain even is, and what has aged
// out.

/** A stored conversation, as much of one as the rules here need. */
export interface ChatRecord {
  id: string;
  /** Registrable domain, e.g. `ebay.com`. The chat's identity. */
  domain: string;
  /** Epoch ms of the last message either way. The retention clock. */
  lastActivityAt: number;
  /** Epoch ms the chat was started. Shown, never used to expire. */
  createdAt: number;
  /** The page the conversation was last on, so reopening it returns there. */
  lastUrl?: string;
  /** First user message, for the list. Absent until they say something. */
  title?: string;
  /** How many messages it holds. A chat with none is not history. */
  messageCount: number;
}

/** How long a chat survives without activity. */
export const RETENTION_CHOICES = [1, 3, 7] as const;
export type RetentionDays = (typeof RETENTION_CHOICES)[number];
export const DEFAULT_RETENTION_DAYS: RetentionDays = 3;

/**
 * How many chats are kept at most, whatever the retention says.
 *
 * localStorage is a handful of megabytes and a full one throws on write, which
 * would lose the conversation being saved rather than an old one. A cap turns
 * that into a prune of the least recently used, which is the outcome anyone
 * would have chosen.
 */
export const MAX_CHATS = 100;

/** Title shown before the user has said anything. */
export const UNTITLED = "New chat";

/**
 * Suffixes where the registrable domain takes THREE labels, not two.
 *
 * Not the full public suffix list — that is thousands of entries and a
 * dependency this package does not want. These cover the multi-part suffixes a
 * user is realistically browsing; anything missed falls back to two labels,
 * which errs toward one chat for `bbc.co.uk` rather than a chat per subdomain.
 */
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "co.in", "net.in", "org.in", "gov.in", "ac.in",
  "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
  "co.za", "co.kr", "co.il", "co.id", "com.pl", "com.ua", "com.ph", "com.vn",
]);

/**
 * The domain a chat belongs to.
 *
 * Returns "" for anything without a real host — a new tab, a file, an
 * extension page — which the caller reads as "no site here to chat about".
 */
export function registrableDomain(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "";
  }
  // Only pages the agent can actually drive. `chrome://extensions` parses
  // perfectly well and yields a hostname of "extensions", which would open a
  // chat about a browser settings page.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
  const host = parsed.hostname.toLowerCase();
  if (!host || host === "localhost") return host;
  // An IP address has no registrable domain; it IS the identity.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return host;

  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");

  const lastTwo = labels.slice(-2).join(".");
  const take = MULTI_PART_SUFFIXES.has(lastTwo) ? 3 : 2;
  return labels.slice(-take).join(".");
}

/**
 * The chat to show for a domain: its most recently active one.
 *
 * Most recent rather than most recently created, because "bring chat1 back"
 * means the conversation they were last having there, and a chat they started
 * and abandoned should not outrank the one they actually used.
 */
export function latestChatFor<T extends ChatRecord>(chats: T[], domain: string): T | undefined {
  if (!domain) return undefined;
  return chats
    .filter(c => c.domain === domain)
    .reduce<T | undefined>((best, c) => (!best || c.lastActivityAt > best.lastActivityAt ? c : best), undefined);
}

/** Whether a chat has aged out, measured from its last activity. */
export function isExpired(chat: ChatRecord, retentionDays: RetentionDays, now: number): boolean {
  return now - chat.lastActivityAt > retentionDays * 24 * 60 * 60 * 1000;
}

/**
 * The history, swept.
 *
 * Two rules, in order. Anything untouched for longer than the retention goes —
 * the clock runs from last activity, so a conversation still in use is never
 * swept, however old it is. Then the cap: if what remains still exceeds
 * MAX_CHATS, the least recently used go, because a write that throws would
 * lose the NEW chat rather than an old one.
 *
 * `keepId` protects the chat currently on screen from both rules. Deleting the
 * conversation someone is looking at is never the right answer to a storage
 * limit.
 */
export function sweepChats<T extends ChatRecord>(
  chats: T[],
  options: { retentionDays: RetentionDays; now: number; keepId?: string },
): T[] {
  const kept = chats.filter(
    c => c.id === options.keepId || !isExpired(c, options.retentionDays, options.now),
  );
  if (kept.length <= MAX_CHATS) return kept;

  const byRecency = [...kept].sort((a, b) => b.lastActivityAt - a.lastActivityAt);
  const survivors = new Set(byRecency.slice(0, MAX_CHATS).map(c => c.id));
  if (options.keepId) survivors.add(options.keepId);
  return kept.filter(c => survivors.has(c.id));
}

/** History as the list shows it: everything, newest activity first. */
export function orderedHistory<T extends ChatRecord>(chats: T[]): T[] {
  return [...chats].sort((a, b) => b.lastActivityAt - a.lastActivityAt);
}

/**
 * Whether a chat is worth remembering.
 *
 * An empty one is not. Starting a new chat twice in a row should not leave two
 * blank rows in the list, and a chat nobody has spoken in has nothing to bring
 * back.
 */
export function isWorthKeeping(chat: ChatRecord): boolean {
  return chat.messageCount > 0;
}

/** How long a title may be before the list truncates it. */
export const MAX_TITLE_LENGTH = 60;

/** A chat's title: what the user first asked, or a placeholder until they do. */
export function titleFrom(firstUserMessage: string | undefined): string {
  const text = firstUserMessage?.replace(/\s+/g, " ").trim();
  if (!text) return UNTITLED;
  return text.length <= MAX_TITLE_LENGTH ? text : `${text.slice(0, MAX_TITLE_LENGTH - 1)}…`;
}
