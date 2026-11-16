"""
rudp.py - Reliable UDP, v1  (Member A deliverable)

Features
  * 25-byte header from the P2PSP spec (big-endian, version, CRC32)
  * Selective Repeat sliding window (packet-based sequence numbers)
  * Cumulative ACK + echo of the packet that triggered the ACK (SACK-lite)
  * Adaptive RTO (RFC 6298: SRTT/RTTVAR, Karn's rule, exponential backoff)
  * Receiver-advertised window (flow control), no congestion control
  * Independent streams: every (peer address, stream_id) has its own
    sequence space, so a loss on one stream never blocks another
  * Built-in loss / duplication / reordering simulator for testing

Public API
    s = RUDPSocket(port=9000)
    s.send(addr, b"...", stream=0)     # blocks until fully ACKed
    addr, stream, msg = s.recv(timeout=5)
    s.close()
Messages are length-prefixed internally, so recv() returns exactly what the
peer passed to send(), however large.
"""
import random
import socket
import struct
import threading
import time
import queue
import zlib
from collections import namedtuple

# ---------------------------------------------------------------- wire format
VERSION = 1
HDR_FMT = "!BBBHIIHHII"          # ver,type,flags,stream,seq,ack,wnd,len,sender,crc
HDR_LEN = struct.calcsize(HDR_FMT)   # = 25, no padding because of '!'
assert HDR_LEN == 25

T_DATA = 0x00                    # transport data (app message types live in payload)
T_ACK = 0x20
F_ACK, F_SYN, F_FIN, F_RETX = 0x01, 0x02, 0x04, 0x08

Header = namedtuple("Header", "ver type flags stream seq ack wnd length sender")


def pack(ptype, flags, stream, seq, ack, wnd, sender, payload=b""):
    hdr = struct.pack(HDR_FMT, VERSION, ptype, flags, stream, seq, ack,
                      wnd, len(payload), sender, 0)
    crc = zlib.crc32(hdr + payload) & 0xFFFFFFFF
    return hdr[:-4] + struct.pack("!I", crc) + payload


def unpack(pkt):
    """Return (Header, payload) or None if the packet is invalid."""
    if len(pkt) < HDR_LEN:
        return None
    f = struct.unpack(HDR_FMT, pkt[:HDR_LEN])
    ver, length, crc = f[0], f[7], f[9]
    if ver != VERSION or len(pkt) != HDR_LEN + length:
        return None
    zeroed = pkt[:HDR_LEN - 4] + b"\x00\x00\x00\x00" + pkt[HDR_LEN:]
    if zlib.crc32(zeroed) & 0xFFFFFFFF != crc:
        return None
    return Header(*f[:9]), pkt[HDR_LEN:]


# ------------------------------------------------------------- tunables
MSS = 1000                       # payload bytes per packet (+25 header < MTU)
WINDOW = 64                      # max packets in flight / receive buffer size
RTO_INIT, RTO_MIN, RTO_MAX = 0.2, 0.05, 2.0   # seconds
MAX_RETX = 12                    # give up on a packet after this many retries


# ------------------------------------------------------ network simulator
class LossyLink:
    """Wraps outgoing packets: drop, duplicate and reorder (delay) them."""

    def __init__(self, loss=0.0, dup=0.0, reorder=0.0, max_delay=0.02, seed=None):
        self.loss, self.dup, self.reorder, self.max_delay = loss, dup, reorder, max_delay
        self.rng = random.Random(seed)
        self.stats = {"sent": 0, "dropped": 0, "duplicated": 0, "delayed": 0}

    @staticmethod
    def _raw(sock, pkt, addr):
        try:
            sock.sendto(pkt, addr)
        except OSError:
            pass

    def send(self, sock, pkt, addr):
        r = self.rng
        self.stats["sent"] += 1
        if r.random() < self.loss:
            self.stats["dropped"] += 1
            return
        copies = 1
        if r.random() < self.dup:
            copies = 2
            self.stats["duplicated"] += 1
        for _ in range(copies):
            if r.random() < self.reorder:
                self.stats["delayed"] += 1
                t = threading.Timer(r.uniform(0, self.max_delay), self._raw, (sock, pkt, addr))
                t.daemon = True
                t.start()
            else:
                self._raw(sock, pkt, addr)


# ----------------------------------------------------------- per-stream state
class _Pkt:
    __slots__ = ("data", "sent", "deadline", "retx", "skips")

    def __init__(self, data, now, rto):
        self.data, self.sent, self.deadline, self.retx, self.skips = data, now, now + rto, 0, 0


class _Chan:
    """State for one (peer address, stream id)."""

    def __init__(self):
        # sender side
        self.cv = threading.Condition()
        self.send_lock = threading.Lock()      # one send() at a time per stream
        self.next_seq = 0
        self.unacked = {}                      # seq -> _Pkt
        self.peer_wnd = WINDOW
        self.srtt = self.rttvar = None
        self.rto = RTO_INIT
        # receiver side
        self.rlock = threading.Lock()
        self.rcv_base = 0                      # next in-order seq expected
        self.rbuf = {}                         # out-of-order packets
        self.sbuf = bytearray()                # in-order bytes awaiting framing


# --------------------------------------------------------------- the socket
class RUDPSocket:
    def __init__(self, port=0, host="127.0.0.1", peer_id=None, link=None,
                 max_retx=MAX_RETX):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.addr = self.sock.getsockname()
        self.peer_id = peer_id if peer_id is not None else random.getrandbits(32)
        self.link = link
        self.max_retx = max_retx
        self.inbox = queue.Queue()
        self.stats = {"retx": 0, "bad_pkts": 0, "dup_rx": 0}
        self._chans = {}
        self._chans_lock = threading.Lock()
        self._running = True
        self._rx = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx.start()

    # ---- helpers
    def _chan(self, addr, stream):
        key = (addr, stream)
        with self._chans_lock:
            if key not in self._chans:
                self._chans[key] = _Chan()
            return self._chans[key]

    def _out(self, pkt, addr):
        if self.link:
            self.link.send(self.sock, pkt, addr)
        else:
            try:
                self.sock.sendto(pkt, addr)
            except OSError:
                pass

    # ---- receive path
    def _rx_loop(self):
        while self._running:
            try:
                pkt, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, ConnectionRefusedError):
                continue                      # Windows reports ICMP errors here
            except OSError:
                break
            parsed = unpack(pkt)
            if parsed is None:
                self.stats["bad_pkts"] += 1   # bad checksum/version: drop silently
                continue
            h, payload = parsed
            if h.type == T_ACK:
                self._on_ack(addr, h, payload)
            elif h.type == T_DATA:
                self._on_data(addr, h, payload)

    def _on_data(self, addr, h, payload):
        ch = self._chan(addr, h.stream)
        with ch.rlock:
            if h.seq < ch.rcv_base:
                self.stats["dup_rx"] += 1     # already delivered: just re-ACK
            elif h.seq < ch.rcv_base + WINDOW:
                if h.seq in ch.rbuf:
                    self.stats["dup_rx"] += 1
                else:
                    ch.rbuf[h.seq] = payload
                while ch.rcv_base in ch.rbuf:         # slide the window
                    ch.sbuf += ch.rbuf.pop(ch.rcv_base)
                    ch.rcv_base += 1
                self._extract(addr, h.stream, ch)
            else:
                return                                 # beyond window: ignore
            wnd = max(0, WINDOW - len(ch.rbuf))
            ack = pack(T_ACK, F_ACK, h.stream, 0, ch.rcv_base, wnd,
                       self.peer_id, struct.pack("!I", h.seq))
        self._out(ack, addr)

    def _extract(self, addr, stream, ch):
        sb = ch.sbuf
        while len(sb) >= 4:
            n = struct.unpack_from("!I", sb)[0]
            if len(sb) < 4 + n:
                break
            msg = bytes(sb[4:4 + n])
            del sb[:4 + n]
            self.inbox.put((addr, stream, msg))

    def _on_ack(self, addr, h, payload):
        ch = self._chan(addr, h.stream)
        with ch.cv:
            ch.peer_wnd = h.wnd
            if len(payload) >= 4:                     # echoed seq -> selective ACK
                echo = struct.unpack("!I", payload[:4])[0]
                p = ch.unacked.pop(echo, None)
                for s, q in ch.unacked.items():       # later packet arrived, this one didn't
                    if s < echo:
                        q.skips += 1                  # 3 skips => fast retransmit
                if p is not None and p.retx == 0:     # Karn: sample only if never retransmitted
                    self._rtt_sample(ch, time.monotonic() - p.sent)
            for s in [s for s in ch.unacked if s < h.ack]:   # cumulative ACK
                del ch.unacked[s]
            ch.cv.notify_all()

    @staticmethod
    def _rtt_sample(ch, r):                           # RFC 6298
        if ch.srtt is None:
            ch.srtt, ch.rttvar = r, r / 2
        else:
            ch.rttvar = 0.75 * ch.rttvar + 0.25 * abs(ch.srtt - r)
            ch.srtt = 0.875 * ch.srtt + 0.125 * r
        ch.rto = min(RTO_MAX, max(RTO_MIN, ch.srtt + 4 * ch.rttvar))

    # ---- send path
    def send(self, addr, data, stream=0, timeout=120.0):
        """Reliably deliver `data` to addr on `stream`. Blocks until ACKed.
        Raises ConnectionError if the peer stops responding, TimeoutError on overall timeout."""
        ch = self._chan(addr, stream)
        framed = struct.pack("!I", len(data)) + data
        chunks = [framed[i:i + MSS] for i in range(0, len(framed), MSS)]
        end = time.monotonic() + timeout
        with ch.send_lock, ch.cv:
            last_seq = ch.next_seq + len(chunks)       # exclusive
            idx = 0
            while True:
                now = time.monotonic()
                base = min(ch.unacked) if ch.unacked else ch.next_seq
                if base >= last_seq:
                    return
                if now > end:
                    raise TimeoutError("send timed out")
                # 1) fill the window
                win = max(1, min(WINDOW, ch.peer_wnd))
                while idx < len(chunks) and ch.next_seq - base < win:
                    pkt = pack(T_DATA, 0, stream, ch.next_seq, 0, WINDOW,
                               self.peer_id, chunks[idx])
                    ch.unacked[ch.next_seq] = _Pkt(pkt, now, ch.rto)
                    self._out(pkt, addr)
                    ch.next_seq += 1
                    idx += 1
                # 2) retransmit expired packets (selective repeat)
                for seq, p in list(ch.unacked.items()):
                    if now >= p.deadline or p.skips >= 3:
                        if p.retx >= self.max_retx:
                            raise ConnectionError(f"peer {addr} not responding (seq {seq})")
                        p.retx += 1
                        p.skips = 0
                        self.stats["retx"] += 1
                        flagged = pack(T_DATA, F_RETX, stream, seq, 0, WINDOW,
                                       self.peer_id, p.data[HDR_LEN:])
                        p.data = flagged
                        self._out(flagged, addr)
                        p.deadline = now + min(RTO_MAX, ch.rto * (2 ** p.retx))   # per-packet backoff
                # 3) sleep until ACK arrives or next timer fires
                nxt = min((p.deadline for p in ch.unacked.values()), default=now + 0.05)
                ch.cv.wait(timeout=max(0.002, min(nxt - now, 0.05)))

    def recv(self, timeout=None):
        """Return (addr, stream, message_bytes). Raises queue.Empty on timeout."""
        return self.inbox.get(timeout=timeout)

    def close(self):
        self._running = False
        self._rx.join(timeout=1)
        self.sock.close()
