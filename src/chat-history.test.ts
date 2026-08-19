import { test, expect } from "bun:test";
import {
  DEFAULT_RETENTION_DAYS,
  MAX_CHATS,
  UNTITLED,
  isWorthKeeping,
  latestChatFor,
  orderedHistory,
  registrableDomain,
  sweepChats,
  titleFrom,
  type ChatRecord,
} from "./chat-history";

const DAY = 24 * 60 * 60 * 1000;
const NOW = 1_760_000_000_000;

const chat = (over: Partial<ChatRecord> = {}): ChatRecord => ({
  id: "c1",
  domain: "ebay.com",
  createdAt: NOW,
  lastActivityAt: NOW,
  messageCount: 2,
  ...over,
});

// --- what a domain is -------------------------------------------------------

test("a chat spans a site's subdomains", () => {
  // The case that motivated this: "Save this search" redirected to
  // signin.ebay.com, and a per-host rule would have swapped the chat out
  // mid-task.
  expect(registrableDomain("https://www.ebay.com/sch/i.html")).toBe("ebay.com");
  expect(registrableDomain("https://signin.ebay.com/ws/eBayISAPI.dll")).toBe("ebay.com");
  expect(registrableDomain("http://ebay.com")).toBe("ebay.com");
});

test("different sites are different chats", () => {
  expect(registrableDomain("https://www.amazon.com")).not.toBe(registrableDomain("https://www.ebay.com"));
});

test("handles suffixes where the domain takes three labels", () => {
  // Two labels would make every bbc.co.uk subdomain its own chat, and worse,
  // would merge unrelated sites under "co.uk".
  expect(registrableDomain("https://www.bbc.co.uk/news")).toBe("bbc.co.uk");
  expect(registrableDomain("https://shop.coles.com.au")).toBe("coles.com.au");
});

test("says nothing for a page that is not a site", () => {
  // A new tab, a local file, the extension's own pages: nothing to chat about.
  expect(registrableDomain("about:blank")).toBe("");
  expect(registrableDomain("chrome://extensions")).toBe("");
  expect(registrableDomain("not a url")).toBe("");
});

test("an address with no domain is its own identity", () => {
  expect(registrableDomain("http://127.0.0.1:8080/app")).toBe("127.0.0.1");
  expect(registrableDomain("http://localhost:7177")).toBe("localhost");
});

// --- which chat comes back --------------------------------------------------

test("switching back to a site brings back the chat you were having there", () => {
  const chats = [
    chat({ id: "ebay-old", lastActivityAt: NOW - 2 * DAY }),
    chat({ id: "ebay-recent", lastActivityAt: NOW - 1000 }),
    chat({ id: "amazon", domain: "amazon.com", lastActivityAt: NOW }),
  ];
  expect(latestChatFor(chats, "ebay.com")?.id).toBe("ebay-recent");
  expect(latestChatFor(chats, "amazon.com")?.id).toBe("amazon");
});

test("a site with no chat yet has none, and a new one is started", () => {
  expect(latestChatFor([chat()], "target.com")).toBeUndefined();
  expect(latestChatFor([chat()], "")).toBeUndefined();
});

test("most recently USED wins, not most recently started", () => {
  // A chat someone opened and abandoned should not outrank the one they were
  // actually having.
  const chats = [
    chat({ id: "abandoned", createdAt: NOW, lastActivityAt: NOW - DAY }),
    chat({ id: "in-use", createdAt: NOW - 5 * DAY, lastActivityAt: NOW }),
  ];
  expect(latestChatFor(chats, "ebay.com")?.id).toBe("in-use");
});

// --- what ages out ----------------------------------------------------------

test("a chat untouched for longer than the retention is swept", () => {
  const chats = [
    chat({ id: "stale", lastActivityAt: NOW - 4 * DAY }),
    chat({ id: "fresh", lastActivityAt: NOW - 1 * DAY }),
  ];
  const kept = sweepChats(chats, { retentionDays: DEFAULT_RETENTION_DAYS, now: NOW });
  expect(kept.map(c => c.id)).toEqual(["fresh"]);
});

test("a chat you are still using is never swept, however old", () => {
  // The clock runs from last activity, so a week-old conversation used this
  // morning survives a one-day retention.
  const chats = [chat({ id: "old-but-live", createdAt: NOW - 30 * DAY, lastActivityAt: NOW - 1000 })];
  expect(sweepChats(chats, { retentionDays: 1, now: NOW })).toHaveLength(1);
});

test("the chat on screen survives the sweep even when it has aged out", () => {
  // Deleting the conversation someone is looking at is never the right answer.
  const chats = [chat({ id: "current", lastActivityAt: NOW - 30 * DAY })];
  const kept = sweepChats(chats, { retentionDays: 1, now: NOW, keepId: "current" });
  expect(kept.map(c => c.id)).toEqual(["current"]);
});

test("beyond the cap the least recently used go", () => {
  // A full localStorage throws on WRITE, which would lose the new chat rather
  // than an old one. Pruning turns that into the outcome anyone would choose.
  const many = Array.from({ length: MAX_CHATS + 10 }, (_, i) =>
    chat({ id: `c${i}`, lastActivityAt: NOW - i * 1000 }),
  );
  const kept = sweepChats(many, { retentionDays: 7, now: NOW });
  expect(kept).toHaveLength(MAX_CHATS);
  expect(kept.some(c => c.id === "c0")).toBe(true);
  expect(kept.some(c => c.id === `c${MAX_CHATS + 5}`)).toBe(false);
});

// --- the list ---------------------------------------------------------------

test("history is every domain, newest activity first", () => {
  const chats = [
    chat({ id: "a", domain: "amazon.com", lastActivityAt: NOW - DAY }),
    chat({ id: "b", domain: "ebay.com", lastActivityAt: NOW }),
    chat({ id: "c", domain: "nvidia.com", lastActivityAt: NOW - 2 * DAY }),
  ];
  expect(orderedHistory(chats).map(c => c.id)).toEqual(["b", "a", "c"]);
});

test("an empty chat is not history", () => {
  // Starting a new chat twice should not leave two blank rows.
  expect(isWorthKeeping(chat({ messageCount: 0 }))).toBe(false);
  expect(isWorthKeeping(chat({ messageCount: 1 }))).toBe(true);
});

test("a chat is titled by what was first asked", () => {
  expect(titleFrom("Find me a gaming PC with a 5090")).toBe("Find me a gaming PC with a 5090");
  expect(titleFrom(undefined)).toBe(UNTITLED);
  expect(titleFrom("   ")).toBe(UNTITLED);
});

test("a long first message is truncated, not wrapped across the list", () => {
  const long = "x".repeat(200);
  const title = titleFrom(long);
  expect(title.length).toBeLessThanOrEqual(60);
  expect(title.endsWith("…")).toBe(true);
});
