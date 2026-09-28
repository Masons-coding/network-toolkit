import { test } from "node:test";
import assert from "node:assert/strict";

import { contains, ipToString, parseIp, prefixForHosts, split, subnetInfo, vlsm } from "../src/ipv4.js";
import { lookup, normalizeDomain, parseResponse } from "../src/dns.js";
import { simulateTcp } from "../src/tcp.js";

test("parses and prints IPv4 addresses as unsigned 32-bit integers", () => {
  assert.equal(parseIp("0.0.0.0"), 0);
  assert.equal(parseIp("255.255.255.255"), 4294967295);
  assert.equal(ipToString(parseIp("192.168.1.10")), "192.168.1.10");
  for (const bad of ["256.1.1.1", "1.2.3", "a.b.c.d", "1.2.3.4.5", ""]) assert.throws(() => parseIp(bad));
});

test("subnet math for a /25", () => {
  const s = subnetInfo("192.168.1.130/25");
  assert.equal(s.network, "192.168.1.128");
  assert.equal(s.broadcast, "192.168.1.255");
  assert.equal(s.firstHost, "192.168.1.129");
  assert.equal(s.lastHost, "192.168.1.254");
  assert.equal(s.usable, 126);
  assert.equal(s.mask, "255.255.255.128");
  assert.equal(s.wildcard, "0.0.0.127");
  assert.equal(s.cidr, "192.168.1.128/25");
  assert.equal(s.type.label, "Private");
  assert.equal(s.binary.mask, "11111111.11111111.11111111.10000000");
});

test("edge prefixes: /0, /31 point-to-point, /32 host route", () => {
  assert.equal(subnetInfo("8.8.8.8/0").total, 2 ** 32);
  const p2p = subnetInfo("10.0.0.1/31");
  assert.equal(p2p.usable, 2);
  assert.equal(p2p.broadcast, null);
  const host = subnetInfo("10.0.0.7/32");
  assert.equal(host.usable, 1);
  assert.equal(host.firstHost, "10.0.0.7");
  assert.throws(() => subnetInfo("10.0.0.0/33"));
});

test("classifies special-purpose address ranges", () => {
  const label = (ip) => subnetInfo(`${ip}/32`).type.label;
  assert.equal(label("10.1.2.3"), "Private");
  assert.equal(label("172.20.0.1"), "Private");
  assert.equal(label("172.32.0.1"), "Public"); // just outside 172.16.0.0/12
  assert.equal(label("127.0.0.1"), "Loopback");
  assert.equal(label("169.254.10.10"), "Link-local");
  assert.equal(label("100.64.0.1"), "Carrier-grade NAT");
  assert.equal(label("224.0.0.251"), "Multicast");
  assert.equal(label("8.8.8.8"), "Public");
});

test("contains() checks subnet membership", () => {
  assert.ok(contains("10.0.0.0/8", "10.255.1.1"));
  assert.ok(!contains("192.168.1.0/24", "192.168.2.1"));
  assert.ok(contains("0.0.0.0/0", "1.2.3.4"));
});

test("splitting a /24 into /26 blocks", () => {
  const { count, subnets } = split("192.168.10.0/24", 26);
  assert.equal(count, 4);
  assert.deepEqual(subnets.map((s) => s.cidr), ["192.168.10.0/26", "192.168.10.64/26", "192.168.10.128/26", "192.168.10.192/26"]);
  assert.throws(() => split("10.0.0.0/24", 16));
});

test("prefixForHosts accounts for network + broadcast addresses", () => {
  assert.equal(prefixForHosts(2), 31);
  assert.equal(prefixForHosts(6), 29);
  assert.equal(prefixForHosts(62), 26);
  assert.equal(prefixForHosts(63), 25);
  assert.equal(prefixForHosts(254), 24);
});

test("VLSM allocates largest first on aligned boundaries", () => {
  const plan = vlsm("192.168.0.0/24", [
    { name: "Guests", hosts: 10 },
    { name: "Engineering", hosts: 100 },
    { name: "Sales", hosts: 50 },
    { name: "Router link", hosts: 2 },
  ]);
  assert.deepEqual(
    plan.allocations.map((a) => `${a.name} ${a.cidr}`),
    ["Engineering 192.168.0.0/25", "Sales 192.168.0.128/26", "Guests 192.168.0.192/28", "Router link 192.168.0.208/31"]
  );
  assert.equal(plan.free, 256 - 128 - 64 - 16 - 2);
  assert.throws(() => vlsm("10.0.0.0/28", [{ name: "Too big", hosts: 100 }]), /Not enough space/);
});

test("domain normalisation accepts URLs and rejects junk", () => {
  assert.equal(normalizeDomain("https://GitHub.com/Masons-coding"), "github.com");
  assert.equal(normalizeDomain("example.com."), "example.com");
  for (const bad of ["localhost", "-bad.com", "a..b", "has space.com", "x".repeat(64) + ".com"]) assert.throws(() => normalizeDomain(bad));
});

test("parses DoH JSON responses", () => {
  const r = parseResponse({ Status: 0, AD: true, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "93.184.216.34" }] });
  assert.equal(r.status, "NOERROR");
  assert.ok(r.dnssec);
  assert.deepEqual(r.answers[0], { name: "example.com", type: "A", ttl: 300, data: "93.184.216.34" });
  assert.equal(parseResponse({ Status: 3 }).status, "NXDOMAIN");
});

test("lookup builds the right DoH request (mocked network)", async () => {
  let seen;
  const fakeFetch = async (url, opts) => {
    seen = { url, accept: opts.headers.accept };
    return { ok: true, json: async () => ({ Status: 0, Answer: [{ name: "github.com.", type: 15, TTL: 60, data: "1 aspmx.l.google.com." }] }) };
  };
  const r = await lookup("github.com", "MX", fakeFetch);
  assert.equal(seen.url, "https://cloudflare-dns.com/dns-query?name=github.com&type=MX");
  assert.equal(seen.accept, "application/dns-json");
  assert.equal(r.answers[0].type, "MX");
  await assert.rejects(lookup("github.com", "BOGUS", fakeFetch));
});

test("TCP handshake sequence and acknowledgement numbers", () => {
  const { segments } = simulateTcp({ clientIsn: 100, serverIsn: 300, requestBytes: 0, responseBytes: 0 });
  const [syn, synAck, ack] = segments;
  assert.deepEqual([syn.flags, syn.seq, syn.ack], [["SYN"], 100, null]);
  assert.deepEqual([synAck.flags, synAck.seq, synAck.ack], [["SYN", "ACK"], 300, 101]);
  assert.deepEqual([ack.flags, ack.seq, ack.ack], [["ACK"], 101, 301]);
  assert.equal(ack.clientState, "ESTABLISHED");
  const last = segments.at(-1);
  assert.equal(last.clientState, "TIME_WAIT");
  assert.equal(last.serverState, "CLOSED");
  assert.equal(segments.length, 3 + 4);
});

test("data is segmented by MSS and acknowledged cumulatively", () => {
  const { segments, summary } = simulateTcp({ clientIsn: 0, serverIsn: 0, requestBytes: 2500, responseBytes: 0, mss: 1000 });
  const data = segments.filter((s) => s.len > 0);
  assert.deepEqual(data.map((s) => s.len), [1000, 1000, 500]);
  assert.deepEqual(data.map((s) => s.seq), [1, 1001, 2001]);
  const acks = segments.filter((s) => s.from === "server" && s.flags.join() === "ACK" && s.ack > 1);
  assert.deepEqual(acks.slice(0, 3).map((s) => s.ack), [1001, 2001, 2501]);
  assert.equal(summary.bytesDelivered, 2500);
});

test("a lost segment is retransmitted with the same sequence number", () => {
  const { segments, summary } = simulateTcp({ requestBytes: 3000, responseBytes: 0, mss: 1000, loseSegment: 1 });
  const lost = segments.find((s) => s.lost);
  const retry = segments.find((s) => s.retransmit);
  assert.equal(retry.seq, lost.seq);
  assert.equal(summary.retransmissions, 1);
  assert.equal(summary.bytesDelivered, 3000);
});
