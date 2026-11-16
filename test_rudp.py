"""Standalone tests for rudp.py. Run:  python test_rudp.py"""
import hashlib
import os
import queue
import threading
import time

import rudp
from rudp import RUDPSocket, LossyLink


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def test_header():
    pkt = rudp.pack(rudp.T_DATA, 0, 3, 42, 7, 64, 0xABCD, b"hello")
    assert len(pkt) == 25 + 5
    h, payload = rudp.unpack(pkt)
    assert (h.stream, h.seq, h.ack, h.wnd, h.sender, payload) == (3, 42, 7, 64, 0xABCD, b"hello")
    bad = bytearray(pkt)
    bad[-1] ^= 0xFF                                   # corrupt one payload byte
    assert rudp.unpack(bytes(bad)) is None
    assert rudp.unpack(pkt[:10]) is None              # truncated
    print("PASS header pack/unpack + corruption detection")


def transfer(size_mb, loss, dup, reorder, label, seed=1):
    data = os.urandom(int(size_mb * 1024 * 1024))
    rx = RUDPSocket(link=LossyLink(loss, dup, reorder, seed=seed + 1))   # lossy ACKs
    tx = RUDPSocket(link=LossyLink(loss, dup, reorder, seed=seed))       # lossy DATA
    t0 = time.time()
    th = threading.Thread(target=lambda: tx.send(rx.addr, data))
    th.start()
    _, _, got = rx.recv(timeout=120)
    th.join()
    dt = time.time() - t0
    ok = sha(got) == sha(data)
    print(f"{'PASS' if ok else 'FAIL'} {label}: {size_mb} MB in {dt:.1f}s "
          f"({size_mb / dt:.2f} MB/s) | sent sha={sha(data)} recv sha={sha(got)} | "
          f"data pkts dropped={tx.link.stats['dropped']} dup={tx.link.stats['duplicated']} "
          f"reordered={tx.link.stats['delayed']} retransmits={tx.stats['retx']} "
          f"dup_rx={rx.stats['dup_rx']}")
    assert ok
    tx.close(); rx.close()


def test_dead_receiver():
    tx = RUDPSocket(max_retx=4)
    t0 = time.time()
    try:
        tx.send(("127.0.0.1", 59999), b"x" * 5000, timeout=60)
        raise AssertionError("should have failed")
    except ConnectionError:
        print(f"PASS dead receiver: gave up cleanly after {time.time() - t0:.1f}s")
    tx.close()


def test_streams_independent():
    rx = RUDPSocket()
    tx = RUDPSocket(link=LossyLink(loss=0.2, seed=5))
    msgs = {0: os.urandom(100_000), 1: os.urandom(100_000), 2: os.urandom(100_000)}
    ths = [threading.Thread(target=tx.send, args=(rx.addr, m, s)) for s, m in msgs.items()]
    [t.start() for t in ths]
    got = {}
    for _ in msgs:
        _, s, m = rx.recv(timeout=60)
        got[s] = m
    [t.join() for t in ths]
    assert all(got[s] == msgs[s] for s in msgs)
    print("PASS 3 concurrent streams over one socket, 20% loss, all intact")
    tx.close(); rx.close()


def test_many_small_messages_in_order():
    rx = RUDPSocket()
    tx = RUDPSocket(link=LossyLink(loss=0.2, dup=0.1, reorder=0.2, seed=9))
    N = 300
    th = threading.Thread(target=lambda: [tx.send(rx.addr, f"msg-{i}".encode(), 1) for i in range(N)])
    th.start()
    got = [rx.recv(timeout=60)[2].decode() for _ in range(N)]
    th.join()
    assert got == [f"msg-{i}" for i in range(N)]
    try:
        rx.recv(timeout=0.5)
        raise AssertionError("duplicate delivered")
    except queue.Empty:
        pass
    print(f"PASS {N} small messages: in order, no duplicates (loss 20%, dup 10%, reorder 20%)")
    tx.close(); rx.close()


if __name__ == "__main__":
    test_header()
    transfer(1, 0.0, 0.0, 0.0, "clean link, 1 MB")
    transfer(5, 0.0, 0.0, 0.0, "clean link, 5 MB")
    transfer(5, 0.20, 0.05, 0.10, "20% loss + dup + reorder, 5 MB")
    transfer(2, 0.30, 0.05, 0.10, "30% loss, 2 MB")
    test_streams_independent()
    test_many_small_messages_in_order()
    test_dead_receiver()
    print("\nALL TESTS PASSED")
