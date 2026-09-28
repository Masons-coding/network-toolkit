// DNS lookups over HTTPS (DoH, RFC 8484 JSON flavour) via Cloudflare's public resolver.
// Encrypted DNS: the query travels inside TLS instead of plaintext UDP port 53.

export const RESOLVER = "https://cloudflare-dns.com/dns-query";

export const RECORD_TYPES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 257: "CAA" };

export const RCODES = {
  0: ["NOERROR", "The query succeeded."],
  1: ["FORMERR", "The server couldn't understand the query."],
  2: ["SERVFAIL", "The authoritative server failed to answer (often a DNSSEC problem)."],
  3: ["NXDOMAIN", "That domain doesn't exist."],
  4: ["NOTIMP", "The server doesn't support this kind of query."],
  5: ["REFUSED", "The server refused to answer."],
};

export function normalizeDomain(input) {
  let name = String(input).trim().toLowerCase();
  name = name.replace(/^[a-z]+:\/\//, "").split(/[/?#]/)[0].replace(/\.$/, ""); // accept pasted URLs
  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
  if (!name || name.length > 253 || !name.split(".").every((l) => label.test(l)) || !name.includes(".")) {
    throw new Error(`"${input}" isn't a valid domain name`);
  }
  return name;
}

export function parseResponse(json) {
  const [code, meaning] = RCODES[json.Status] ?? [`RCODE ${json.Status}`, "Unknown response code."];
  const answers = (json.Answer ?? []).map((a) => ({
    name: a.name.replace(/\.$/, ""),
    type: RECORD_TYPES[a.type] ?? `TYPE${a.type}`,
    ttl: a.TTL,
    data: a.data,
  }));
  return {
    status: code,
    meaning,
    ok: json.Status === 0,
    dnssec: Boolean(json.AD),
    truncated: Boolean(json.TC),
    answers,
    authority: (json.Authority ?? []).map((a) => ({ name: a.name, type: RECORD_TYPES[a.type] ?? a.type, data: a.data })),
  };
}

export async function lookup(domain, type = "A", fetchImpl = fetch) {
  const name = normalizeDomain(domain);
  if (!Object.values(RECORD_TYPES).includes(type)) throw new Error(`Unsupported record type ${type}`);
  const url = `${RESOLVER}?name=${encodeURIComponent(name)}&type=${type}`;
  const t0 = performance.now();
  const res = await fetchImpl(url, { headers: { accept: "application/dns-json" } });
  if (!res.ok) throw new Error(`Resolver returned HTTP ${res.status}`);
  const json = await res.json();
  return { name, type, ms: performance.now() - t0, ...parseResponse(json) };
}
