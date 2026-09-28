// IPv4 addressing math: everything is done on unsigned 32-bit integers with bitwise ops.

export function parseIp(text) {
  const parts = String(text).trim().split(".");
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) {
    throw new Error(`"${text}" is not a valid IPv4 address`);
  }
  return parts.reduce((acc, p) => ((acc << 8) | Number(p)) >>> 0, 0);
}

export const ipToString = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");

export const toBinary = (n) =>
  [24, 16, 8, 0].map((s) => ((n >>> s) & 255).toString(2).padStart(8, "0")).join(".");

export const prefixToMask = (prefix) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);

export function parseCidr(text) {
  const [ipPart, prefixPart = "32"] = String(text).trim().split("/");
  if (!/^\d{1,2}$/.test(prefixPart) || Number(prefixPart) > 32) throw new Error(`"/${prefixPart}" is not a valid prefix length (0–32)`);
  return { ip: parseIp(ipPart), prefix: Number(prefixPart) };
}

// RFC-defined special ranges, most specific first
const RANGES = [
  ["127.0.0.0/8", "Loopback", "RFC 1122"],
  ["10.0.0.0/8", "Private", "RFC 1918"],
  ["172.16.0.0/12", "Private", "RFC 1918"],
  ["192.168.0.0/16", "Private", "RFC 1918"],
  ["100.64.0.0/10", "Carrier-grade NAT", "RFC 6598"],
  ["169.254.0.0/16", "Link-local", "RFC 3927"],
  ["224.0.0.0/4", "Multicast", "RFC 5771"],
  ["240.0.0.0/4", "Reserved", "RFC 1112"],
  ["0.0.0.0/8", "\"This\" network", "RFC 1122"],
];

export function contains(cidr, ipText) {
  const { ip, prefix } = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  const mask = prefixToMask(prefix);
  return ((parseIp(ipText) & mask) >>> 0) === ((ip & mask) >>> 0);
}

export function classify(ip) {
  const text = ipToString(ip);
  for (const [range, label, rfc] of RANGES) if (contains(range, text)) return { label, rfc };
  return { label: "Public", rfc: null };
}

export function legacyClass(ip) {
  const first = ip >>> 24;
  if (first < 128) return "A";
  if (first < 192) return "B";
  if (first < 224) return "C";
  if (first < 240) return "D (multicast)";
  return "E (reserved)";
}

export function subnetInfo(text) {
  const { ip, prefix } = parseCidr(text);
  const mask = prefixToMask(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const total = 2 ** (32 - prefix);

  // /31 point-to-point links (RFC 3021) and /32 host routes have no network/broadcast overhead
  let firstHost;
  let lastHost;
  let usable;
  if (prefix >= 31) {
    firstHost = network;
    lastHost = broadcast;
    usable = total;
  } else {
    firstHost = network + 1;
    lastHost = broadcast - 1;
    usable = total - 2;
  }

  return {
    input: ipToString(ip),
    prefix,
    cidr: `${ipToString(network)}/${prefix}`,
    network: ipToString(network),
    broadcast: prefix >= 31 ? null : ipToString(broadcast),
    firstHost: ipToString(firstHost),
    lastHost: ipToString(lastHost),
    usable,
    total,
    mask: ipToString(mask),
    wildcard: ipToString(~mask >>> 0),
    legacyClass: legacyClass(ip),
    type: classify(ip),
    hostOffset: ip - network,
    binary: { ip: toBinary(ip), mask: toBinary(mask), network: toBinary(network) },
  };
}

// Divide a network into equal smaller subnets
export function split(text, newPrefix, limit = 256) {
  const { ip, prefix } = parseCidr(text);
  if (newPrefix < prefix || newPrefix > 32) throw new Error(`Can't split a /${prefix} into /${newPrefix}s`);
  const count = 2 ** (newPrefix - prefix);
  const size = 2 ** (32 - newPrefix);
  const base = (ip & prefixToMask(prefix)) >>> 0;
  return {
    count,
    subnets: Array.from({ length: Math.min(count, limit) }, (_, i) => subnetInfo(`${ipToString(base + i * size)}/${newPrefix}`)),
  };
}

// Smallest prefix that fits `hosts` usable addresses (+ network and broadcast)
export function prefixForHosts(hosts) {
  if (!(hosts >= 1)) throw new Error("Host count must be at least 1");
  if (hosts === 1) return 32;
  if (hosts === 2) return 31;
  const bits = Math.ceil(Math.log2(hosts + 2));
  if (bits > 32) throw new Error("Too many hosts for IPv4");
  return 32 - bits;
}

// Variable Length Subnet Masking: allocate the biggest requirement first so every block
// lands on a boundary aligned to its own size.
export function vlsm(baseText, requirements) {
  const { ip, prefix } = parseCidr(baseText);
  const base = (ip & prefixToMask(prefix)) >>> 0;
  const end = base + 2 ** (32 - prefix);
  const sorted = [...requirements].map((r, order) => ({ ...r, order, prefix: prefixForHosts(r.hosts) })).sort((a, b) => a.prefix - b.prefix || a.order - b.order);

  let cursor = base;
  const allocations = sorted.map((r) => {
    const size = 2 ** (32 - r.prefix);
    cursor = Math.ceil(cursor / size) * size; // align
    if (cursor + size > end) throw new Error(`Not enough space in ${baseText} for "${r.name}" (${r.hosts} hosts)`);
    const info = subnetInfo(`${ipToString(cursor)}/${r.prefix}`);
    cursor += size;
    return { name: r.name, requested: r.hosts, ...info, wasted: info.usable - r.hosts };
  });
  const used = allocations.reduce((s, a) => s + a.total, 0);
  return { allocations, used, available: end - base, free: end - base - used };
}
