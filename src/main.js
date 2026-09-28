import { contains, parseCidr, split, subnetInfo, vlsm } from "./ipv4.js";
import { lookup } from "./dns.js";
import { simulateTcp } from "./tcp.js";
import { initTabs } from "./ui/tabs.js";

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
};
const fmt = (n) => n.toLocaleString("en-US");
const COLORS = ["#00adff", "#22c55e", "#febc2e", "#a78bfa", "#e34f26", "#f472b6", "#2dd4bf", "#fb923c"];

/* =====================================================================
 * Subnet calculator
 * ===================================================================*/
let current = null;

function fact(label, value) {
  return el("div", { className: "fact" }, el("dt", { textContent: label }), el("dd", { textContent: value }));
}

function binaryRow(label, bits, prefix) {
  let seen = 0;
  const spans = [...bits].map((ch) => {
    if (ch === ".") return el("span", { className: "muted", textContent: "." });
    return el("span", { className: seen++ < prefix ? "bit-net" : "bit-host", textContent: ch });
  });
  return [el("span", { className: "label", textContent: label }), el("span", {}, ...spans)];
}

function renderSubnet() {
  try {
    const s = subnetInfo($("cidr").value);
    current = s;
    $("cidr-error").hidden = true;
    $("prefix").value = s.prefix;
    $("prefix-out").textContent = `/${s.prefix}`;
    $("facts").replaceChildren(
      fact("Network", s.cidr),
      fact("Broadcast", s.broadcast ?? "— (/31 & /32 have none)"),
      fact("Usable host range", `${s.firstHost} – ${s.lastHost}`),
      fact("Usable hosts", fmt(s.usable)),
      fact("Subnet mask", s.mask),
      fact("Wildcard mask", s.wildcard),
      fact("Address type", `${s.type.label}${s.type.rfc ? ` (${s.type.rfc})` : ""}`),
      fact("Legacy class", s.legacyClass)
    );
    $("binary").replaceChildren(...binaryRow("Address", s.binary.ip, s.prefix), ...binaryRow("Mask", s.binary.mask, s.prefix), ...binaryRow("Network", s.binary.network, s.prefix));
    $("range-marker").style.left = `${s.total > 1 ? (s.hostOffset / (s.total - 1)) * 100 : 50}%`;
    $("range-lo").textContent = s.network;
    $("range-hi").textContent = s.broadcast ?? s.lastHost;

    // Split options: up to 8 bits smaller
    const select = $("split");
    const keep = Number(select.value) || Math.min(32, s.prefix + 2);
    select.replaceChildren(
      ...Array.from({ length: Math.min(8, 32 - s.prefix) }, (_, i) => {
        const p = s.prefix + i + 1;
        return new Option(`/${p} → ${fmt(2 ** (i + 1))} subnets`, String(p));
      })
    );
    if (select.options.length) select.value = String(Math.max(s.prefix + 1, Math.min(keep, s.prefix + 8, 32)));
    renderSplit();
    renderMembership();
  } catch (err) {
    $("cidr-error").textContent = err.message;
    $("cidr-error").hidden = false;
  }
}

function renderSplit() {
  const table = $("split-table");
  table.replaceChildren();
  if (!current || !$("split").value) return;
  const { count, subnets } = split(current.cidr, Number($("split").value), 64);
  const head = table.createTHead().insertRow();
  for (const h of ["#", "Subnet", "Usable range", "Hosts"]) head.append(el("th", { textContent: h }));
  const body = table.createTBody();
  subnets.forEach((s, i) => {
    const row = el("tr", {}, el("td", { textContent: String(i + 1) }), el("td", { textContent: s.cidr }), el("td", { textContent: `${s.firstHost} – ${s.lastHost}` }), el("td", { textContent: fmt(s.usable) }));
    if (contains(s.cidr, current.input)) row.classList.add("is-current");
    body.append(row);
  });
  if (count > subnets.length) body.append(el("tr", {}, el("td", { colSpan: 4, className: "muted", textContent: `… and ${fmt(count - subnets.length)} more` })));
}

function renderMembership() {
  const out = $("member-result");
  try {
    const inside = contains(current.cidr, $("member").value);
    out.textContent = inside ? `✓ inside ${current.cidr}` : `✗ outside ${current.cidr}`;
    out.style.color = inside ? "#4ade80" : "#ff8a65";
  } catch (err) {
    out.textContent = err.message;
    out.style.color = "#febc2e";
  }
}

$("cidr").addEventListener("input", renderSubnet);
$("prefix").addEventListener("input", (e) => {
  try {
    const ip = $("cidr").value.split("/")[0];
    parseCidr(`${ip}/${e.target.value}`);
    $("cidr").value = `${ip}/${e.target.value}`;
    renderSubnet();
  } catch {
    /* keep the text box as-is while it's invalid */
  }
});
$("split").addEventListener("change", renderSplit);
$("member").addEventListener("input", renderMembership);

/* ---------------- VLSM ---------------- */
const DEFAULT_TEAMS = [
  ["Engineering", 300],
  ["Sales", 120],
  ["Guest Wi-Fi", 60],
  ["Servers", 25],
  ["Printers", 10],
  ["WAN link", 2],
];

function vlsmRow(name = "", hosts = 10) {
  const nameInput = el("input", { type: "text", value: name, placeholder: "Team / VLAN" });
  const hostsInput = el("input", { type: "number", value: String(hosts), min: "1", max: "16777214" });
  nameInput.setAttribute("aria-label", "Subnet name");
  hostsInput.setAttribute("aria-label", "Hosts needed");
  const remove = el("button", { className: "remove", type: "button", textContent: "✕", title: "Remove" });
  const row = el("tr", {}, el("td", {}, nameInput), el("td", {}, hostsInput), el("td", {}, remove));
  remove.addEventListener("click", () => {
    row.remove();
    runVlsm();
  });
  return row;
}

function runVlsm() {
  const reqs = [...$("vlsm-rows").querySelectorAll("tr")].map((row, i) => {
    const [name, hosts] = row.querySelectorAll("input");
    return { name: name.value.trim() || `Subnet ${i + 1}`, hosts: Math.floor(Number(hosts.value)) };
  });
  const table = $("vlsm-table");
  table.replaceChildren();
  $("vlsm-usage").replaceChildren();
  try {
    if (reqs.some((r) => !(r.hosts >= 1))) throw new Error("Every subnet needs at least 1 host");
    const plan = vlsm($("vlsm-base").value, reqs);
    $("vlsm-error").hidden = true;
    const head = table.createTHead().insertRow();
    for (const h of ["Name", "Needs", "Subnet", "Usable range", "Usable", "Spare"]) head.append(el("th", { textContent: h }));
    const body = table.createTBody();
    plan.allocations.forEach((a, i) => {
      const dot = el("span", { className: "tag", textContent: a.name });
      dot.style.borderColor = COLORS[i % COLORS.length];
      body.append(el("tr", {}, el("td", {}, dot), el("td", { textContent: fmt(a.requested) }), el("td", { textContent: a.cidr }), el("td", { textContent: `${a.firstHost} – ${a.lastHost}` }), el("td", { textContent: fmt(a.usable) }), el("td", { textContent: fmt(a.wasted) })));
      const block = el("div", { className: "usage__block", textContent: a.name, title: `${a.name}: ${a.cidr}` });
      block.style.flex = `${a.total} 0 0`;
      block.style.background = COLORS[i % COLORS.length];
      $("vlsm-usage").append(block);
    });
    if (plan.free) {
      const free = el("div", { className: "usage__block usage__block--free", textContent: `free ${fmt(plan.free)}` });
      free.style.flex = `${plan.free} 0 0`;
      $("vlsm-usage").append(free);
    }
  } catch (err) {
    $("vlsm-error").textContent = err.message;
    $("vlsm-error").hidden = false;
  }
}

$("vlsm-rows").append(...DEFAULT_TEAMS.map(([n, h]) => vlsmRow(n, h)));
$("vlsm-add").addEventListener("click", () => {
  $("vlsm-rows").append(vlsmRow("", 10));
  runVlsm();
});
$("vlsm-run").addEventListener("click", runVlsm);
$("vlsm-base").addEventListener("change", runVlsm);
$("vlsm-rows").addEventListener("change", runVlsm);

/* =====================================================================
 * DNS
 * ===================================================================*/
function answerTable(answers) {
  if (!answers.length) return el("p", { className: "muted small", textContent: "No records of this type." });
  const table = el("table");
  const head = table.createTHead().insertRow();
  for (const h of ["Name", "Type", "TTL", "Data"]) head.append(el("th", { textContent: h }));
  const body = table.createTBody();
  for (const a of answers) body.append(el("tr", {}, el("td", { textContent: a.name }), el("td", { textContent: a.type }), el("td", { textContent: `${a.ttl}s` }), el("td", { textContent: a.data })));
  return el("div", { className: "table-wrap" }, table);
}

function statusBadges(r) {
  return el(
    "div",
    { className: "status" },
    el("span", { className: `tag ${r.ok ? "tag--good" : "tag--bad"}`, textContent: r.status }),
    r.dnssec ? el("span", { className: "tag tag--good", textContent: "🔏 DNSSEC validated" }) : "",
    el("span", { className: "muted", textContent: r.meaning })
  );
}

async function resolve(types) {
  const domain = $("domain").value;
  $("dns-results").replaceChildren(el("p", { className: "muted", textContent: "Resolving…" }));
  $("dns-status").replaceChildren();
  $("dns-meta").textContent = "";
  try {
    const t0 = performance.now();
    const results = await Promise.all(types.map((t) => lookup(domain, t)));
    const ms = performance.now() - t0;
    $("dns-meta").textContent = `${results[0].name} · ${ms.toFixed(0)} ms via cloudflare-dns.com (HTTPS)`;
    $("dns-status").replaceChildren(statusBadges(results[0]));
    if (types.length === 1) $("dns-results").replaceChildren(answerTable(results[0].answers));
    else {
      $("dns-results").replaceChildren(
        ...results.map((r) => el("div", { className: "dns-group" }, el("h3", { textContent: `${r.type} (${r.answers.filter((a) => a.type === r.type).length})` }), answerTable(r.answers)))
      );
    }
  } catch (err) {
    $("dns-results").replaceChildren(el("p", { className: "error", textContent: err.message }));
  }
}

$("dns-run").addEventListener("click", () => resolve([$("rtype").value]));
$("dns-all").addEventListener("click", () => resolve(["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"]));
$("domain").addEventListener("keydown", (e) => {
  if (e.key === "Enter") resolve([$("rtype").value]);
});
document.querySelectorAll("[data-domain]").forEach((b) =>
  b.addEventListener("click", () => {
    $("domain").value = b.dataset.domain;
    $("rtype").value = b.dataset.type || "A";
    resolve([$("rtype").value]);
  })
);

/* =====================================================================
 * TCP
 * ===================================================================*/
const tcp = { segments: [], shown: 0, timer: null, clientIsn: 0, serverIsn: 0 };
const randomIsn = () => Math.floor(Math.random() * 90000) + 1000;

function buildConnection(newIsns) {
  if (newIsns) {
    tcp.clientIsn = randomIsn();
    tcp.serverIsn = randomIsn();
  }
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Math.floor(Number(v)) || 0));
  const { segments, summary } = simulateTcp({
    clientIsn: tcp.clientIsn,
    serverIsn: tcp.serverIsn,
    requestBytes: clamp($("req").value, 0, 20000),
    responseBytes: clamp($("res").value, 0, 20000),
    mss: clamp($("mss").value, 100, 9000),
    loseSegment: $("lose").checked ? 1 : null,
  });
  tcp.segments = segments;
  tcp.shown = 0;
  stopTcp();
  $("timeline").replaceChildren();
  $("client-state").textContent = "CLOSED";
  $("server-state").textContent = "LISTEN";
  const stat = (label, value) => el("div", { className: "stat" }, el("span", { className: "stat__label", textContent: label }), el("span", { className: "stat__value", textContent: value }));
  $("tcp-stats").replaceChildren(
    stat("Segments", String(summary.total)),
    stat("Data segments", String(summary.dataSegments)),
    stat("Retransmits", String(summary.retransmissions)),
    stat("Header bytes", fmt(summary.overhead))
  );
  $("tcp-step").disabled = false;
  $("tcp-play").disabled = false;
}

function segmentRow(s) {
  const flags = s.flags.join("-");
  const cls = ["seg", s.from === "client" ? "seg--right" : "seg--left"];
  if (s.flags.includes("SYN")) cls.push("seg--syn");
  else if (s.flags.includes("FIN")) cls.push("seg--fin");
  else if (s.len > 0) cls.push("seg--data");
  if (s.lost) cls.push("seg--lost");
  if (s.retransmit) cls.push("seg--retransmit");
  const label = el("div", { className: "seg__arrow" }, el("span", { className: "flags", textContent: flags }), ` seq=${s.seq}${s.ack !== null ? ` ack=${s.ack}` : ""}${s.len ? ` len=${s.len}` : ""}`);
  return el(
    "li",
    { className: cls.join(" ") },
    el("span", { className: "seg__state", textContent: s.clientState }),
    label,
    el("span", { className: "seg__state seg__state--right", textContent: s.serverState }),
    el("span", { className: "seg__note", textContent: s.note })
  );
}

function stepTcp() {
  if (tcp.shown >= tcp.segments.length) {
    stopTcp();
    $("tcp-step").disabled = true;
    $("tcp-play").disabled = true;
    return false;
  }
  const s = tcp.segments[tcp.shown++];
  const row = segmentRow(s);
  $("timeline").append(row);
  row.scrollIntoView({ block: "nearest" });
  $("client-state").textContent = s.clientState;
  $("server-state").textContent = s.serverState;
  if (tcp.shown >= tcp.segments.length) {
    $("tcp-step").disabled = true;
    $("tcp-play").disabled = true;
    stopTcp();
  }
  return true;
}

function stopTcp() {
  clearInterval(tcp.timer);
  tcp.timer = null;
  $("tcp-play").textContent = "▶ Play";
}

$("tcp-play").addEventListener("click", () => {
  if (tcp.timer) return stopTcp();
  $("tcp-play").textContent = "❚❚ Pause";
  stepTcp();
  tcp.timer = setInterval(stepTcp, Number($("tcp-speed").value));
});
$("tcp-step").addEventListener("click", () => {
  stopTcp();
  stepTcp();
});
$("tcp-reset").addEventListener("click", () => buildConnection(true));
for (const id of ["req", "res", "mss", "lose"]) $(id).addEventListener("change", () => buildConnection(false));

/* =====================================================================
 * Boot
 * ===================================================================*/
initTabs();
renderSubnet();
runVlsm();
buildConnection(true);
