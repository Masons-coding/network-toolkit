// TCP connection simulator: three-way handshake, segmented data transfer with cumulative
// ACKs, optional packet loss + retransmission, and the four-way close — with the state of
// each endpoint after every segment (RFC 793 state machine).

export function simulateTcp({ clientIsn = 1000, serverIsn = 5000, requestBytes = 1200, responseBytes = 3000, mss = 1000, loseSegment = null } = {}) {
  if (!(mss >= 1)) throw new Error("MSS must be at least 1 byte");
  const segments = [];
  let clientSeq = clientIsn;
  let serverSeq = serverIsn;
  let clientState = "CLOSED";
  let serverState = "LISTEN";
  let dataIndex = 0; // counts data-carrying segments, for loss injection

  const send = (from, flags, seq, ack, len, note, states, extra = {}) => {
    if (states.client) clientState = states.client;
    if (states.server) serverState = states.server;
    segments.push({ from, to: from === "client" ? "server" : "client", flags, seq, ack, len, note, clientState, serverState, ...extra });
  };

  // ---- Three-way handshake ----
  send("client", ["SYN"], clientSeq, null, 0, "Client picks a random initial sequence number (ISN)", { client: "SYN_SENT" });
  clientSeq += 1; // SYN consumes one sequence number
  send("server", ["SYN", "ACK"], serverSeq, clientSeq, 0, "Server ACKs the client's ISN + 1 and sends its own ISN", { server: "SYN_RECEIVED" });
  serverSeq += 1;
  send("client", ["ACK"], clientSeq, serverSeq, 0, "Handshake complete — both sides agree on sequence numbers", { client: "ESTABLISHED", server: "ESTABLISHED" });

  // ---- Data transfer: sender splits into MSS-sized segments, receiver ACKs cumulatively ----
  const transfer = (from, total, label) => {
    let sent = 0;
    while (sent < total) {
      const len = Math.min(mss, total - sent);
      const seq = from === "client" ? clientSeq : serverSeq;
      const ack = from === "client" ? serverSeq : clientSeq;
      const index = dataIndex++;
      if (index === loseSegment) {
        send(from, ["PSH", "ACK"], seq, ack, len, `${label} bytes ${sent + 1}–${sent + len} … lost in the network ✗`, {}, { lost: true });
        send(from, ["PSH", "ACK"], seq, ack, len, "Retransmission timeout fires — sender resends the same bytes", {}, { retransmit: true });
      } else {
        send(from, ["PSH", "ACK"], seq, ack, len, `${label} bytes ${sent + 1}–${sent + len}`, {});
      }
      if (from === "client") clientSeq += len;
      else serverSeq += len;
      sent += len;
      const receiver = from === "client" ? "server" : "client";
      const rSeq = receiver === "client" ? clientSeq : serverSeq;
      const rAck = receiver === "client" ? serverSeq : clientSeq;
      send(receiver, ["ACK"], rSeq, rAck, 0, `ACK ${rAck}: "I've received everything before byte ${rAck}"`, {});
    }
  };
  transfer("client", requestBytes, "Request");
  transfer("server", responseBytes, "Response");

  // ---- Four-way close ----
  send("client", ["FIN", "ACK"], clientSeq, serverSeq, 0, "Client is done sending", { client: "FIN_WAIT_1" });
  clientSeq += 1; // FIN consumes one sequence number
  send("server", ["ACK"], serverSeq, clientSeq, 0, "Server acknowledges the FIN", { client: "FIN_WAIT_2", server: "CLOSE_WAIT" });
  send("server", ["FIN", "ACK"], serverSeq, clientSeq, 0, "Server is done sending too", { server: "LAST_ACK" });
  serverSeq += 1;
  send("client", ["ACK"], clientSeq, serverSeq, 0, "Client waits 2×MSL in TIME_WAIT for stray packets", { client: "TIME_WAIT", server: "CLOSED" });

  const payload = segments.filter((s) => s.len > 0 && !s.lost);
  return {
    segments,
    summary: {
      total: segments.length,
      dataSegments: payload.length,
      retransmissions: segments.filter((s) => s.retransmit).length,
      bytesDelivered: payload.reduce((n, s) => n + s.len, 0), // lost copies excluded, retransmits included
      overhead: segments.length * 40, // 20-byte IPv4 + 20-byte TCP header per segment
    },
  };
}
