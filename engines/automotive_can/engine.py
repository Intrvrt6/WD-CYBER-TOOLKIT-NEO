"""Module D - Automotive / CAN Bus Pentest.

Real work only: interface enumeration from the kernel and from python-can, real
frame capture and per-ID measurement (periods, counters, checksums), anomaly
detection over the captured frames, an actual replay transmitted on the bus and
confirmed by a second reader, and a genuine ISO-TP/UDS diagnostic exchange
(0x10, 0x22, 0x27, 0x3E) assembled frame by frame over python-can.

Lab mode runs a deterministic multi-ECU vehicle simulator on python-can's
`virtual` interface (userspace, no kernel vcan module needed) that implements
the UDS services above and accepts an injected fault, so timing/anomaly/replay
detection is exercised against traffic that really crossed a bus.  Live mode
uses SocketCAN and reports `unavailable` with the exact kernel reason when no
CAN interface exists - it never invents frames.
"""
from __future__ import annotations

import json
import math
import re
import statistics
import threading
import time
from typing import Any

from backend import runner
from engines.base import Context, Result, unavailable

try:  # python-can is a hard requirement for this module, but import must not kill the platform
    import can
    from can import Bus, Message

    CAN_IMPORT_ERROR = ""
except Exception as _exc:  # pragma: no cover - exercised only on hosts without python-can
    can = None  # type: ignore[assignment]
    Bus = None  # type: ignore[assignment]
    Message = None  # type: ignore[assignment]
    CAN_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"


# ------------------------------------------------------------------ tuning --
UDS_REQ_ID = 0x7E0
UDS_RESP_ID = 0x7E8
PAD = 0x00

LATE_ID_REL = 0.40          # an ID first seen after 40% of the capture window is "late"
PERIOD_DEVIATION_RATIO = 0.30   # split-half mean inter-arrival change that counts as a deviation
JITTER_CV_FLAG = 0.30       # stdev/mean inter-arrival above this is flagged
COUNTER_SKIP_MIN = 1        # counter delta > 1 (mod 256) is a discontinuity
FROZEN_RUN = 5              # consecutive identical payloads that count as frozen
MIN_FRAMES_TIMING = 6       # frames needed before timing statistics are reported
MIN_FRAMES_PERIOD_SPLIT = 8  # frames needed for the split-half period test
MAX_FRAMES = 20000


def _crc8(data: bytes) -> int:
    """CRC-8/SAE-J1850 style (poly 0x1D, init 0xFF) used by the simulated ECUs."""
    crc = 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def _aid_hex(aid: int) -> str:
    return f"0x{aid:X}"


# ============================================================== simulator ====
class VirtualVehicle:
    """Deterministic multi-ECU CAN vehicle simulator on python-can 'virtual'.

    ECUs publish periodic frames at realistic rates; ENGINE and TRANSMISSION
    carry a rolling counter plus a CRC-8, GATEWAY carries a counter only, BODY
    is a static (replay-friendly) body-control frame and BRAKE carries a
    multi-byte pressure signal.  A diag responder answers UDS on 0x7E0/0x7E8
    over a hand-rolled ISO-TP layer.

    `inject_fault()` is applied once, `fault_at` seconds into the run, and
    introduces: a counter skip (ENGINE), a period collapse (TRANSMISSION), a
    DLC change (BODY), a frozen payload (BRAKE) and a brand-new arbitration ID
    (0x6A0).  Detection in CAN-05 never reads this state - it only measures the
    frames that reached the bus.
    """

    INVENTORY = [
        {"ecu": "ENGINE", "tx_ids": ["0x100"], "period_ms": 10, "extended": False,
         "payload": "byte0 rolling counter, byte1 ramp, byte2 rpm-high, byte7 CRC-8"},
        {"ecu": "TRANSMISSION", "tx_ids": ["0x180"], "period_ms": 20, "extended": False,
         "payload": "byte0 rolling counter, gear/rpm bytes, byte7 CRC-8"},
        {"ecu": "BRAKE", "tx_ids": ["0x1F0"], "period_ms": 100, "extended": False,
         "payload": "16-bit brake pressure (byte0 LSB/byte1 MSB), pedal travel byte2"},
        {"ecu": "GATEWAY", "tx_ids": ["0x18FEF100"], "period_ms": 100, "extended": True,
         "payload": "byte0 rolling counter, fixed vehicle-speed bytes (no checksum)"},
        {"ecu": "BODY", "tx_ids": ["0x2A0"], "period_ms": 500, "extended": False,
         "payload": "static body/comfort status - no counter, no checksum"},
        {"ecu": "DIAG", "tx_ids": ["0x7E8"], "period_ms": 0, "extended": False,
         "payload": "UDS responder on request 0x7E0 (ISO-TP, services 0x10/0x22/0x27/0x3E)",
         "rx_id": "0x7E0"},
    ]

    BASE_SCHEDULE = {
        0x100: 0.010,
        0x180: 0.020,
        0x1F0: 0.100,
        0x2A0: 0.500,
        0x18FEF100: 0.100,
    }

    # UDS state
    VIN = b"WDCTEST1234567890"          # 17 bytes -> multi-frame ISO-TP response
    HW_NUMBER = b"HW26A"                # short DID -> single-frame response
    PROTECTED_PAYLOAD = b"PROTECTED-CFG"  # 13 bytes -> multi-frame response
    SEED_KEY_MUL = 0x1234
    SEED_KEY_ADD = 0xABCD
    MAX_ATTEMPTS = 5

    def __init__(self, channel: str, fault_at: float | None = None) -> None:
        self.channel = channel
        self.fault_at = fault_at
        self.faulted = False
        self.tx_frames = 0
        self.uds_requests = 0
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._pause_started = 0.0
        self._lock = threading.Lock()
        self._counters: dict[int, int] = {aid: 0 for aid in self.BASE_SCHEDULE}
        self._ticks: dict[int, int] = {aid: 0 for aid in self.BASE_SCHEDULE}
        self._schedule = dict(self.BASE_SCHEDULE)
        self._next_due: dict[int, float] = {}
        self._engine_skip_pending = False
        self._brake_frozen: bytes | None = None
        self._body_dlc4 = False
        # UDS state
        self._session = 1
        self._unlocked = False
        self._seed = b"\x00\x00\x00\x00"
        self._seed_serial = 0
        self._attempts = 0
        self._threshold = 1000
        self._seed_base = 0x51A7C0DE
        self._threads: list[threading.Thread] = []
        self._tx_bus = Bus(interface="virtual", channel=channel)  # type: ignore[misc]
        self._uds_bus = Bus(interface="virtual", channel=channel)  # type: ignore[misc]

    # ------------------------------------------------------------- lifecycle --
    def start(self) -> None:
        self._t0 = time.monotonic()
        for target in (self._tx_loop, self._uds_loop):
            th = threading.Thread(target=target, daemon=True, name=f"sim-{target.__name__}")
            th.start()
            self._threads.append(th)

    def stop(self) -> None:
        self._stop.set()
        for th in self._threads:
            th.join(timeout=2.0)
        for bus in (self._tx_bus, self._uds_bus):
            try:
                bus.shutdown()
            except Exception:
                pass

    def pause(self) -> None:
        self._pause_started = time.monotonic()
        self._paused.set()

    def resume(self) -> None:
        self._paused.clear()
        shift = time.monotonic() - self._pause_started
        for aid in self._next_due:
            self._next_due[aid] += shift

    # the session drives these so replay works identically in live mode
    def pause_vehicle(self) -> None:
        self.pause()

    def resume_vehicle(self) -> None:
        self.resume()

    def inventory(self) -> list[dict]:
        rows = []
        for row in self.INVENTORY:
            item = dict(row)
            if item["tx_ids"] and item["tx_ids"][0].startswith("0x"):
                aid = int(item["tx_ids"][0], 16)
                item["measured_frames"] = self._counters.get(aid, 0) if aid in self._counters else 0
            rows.append(item)
        return rows

    # ------------------------------------------------------------ TX thread --
    def _tx_loop(self) -> None:
        self._next_due = {aid: self._t0 for aid in self._schedule}
        while not self._stop.is_set():
            try:
                now = time.monotonic()
                if self._paused.is_set():
                    time.sleep(0.002)
                    continue
                if not self.faulted and self.fault_at is not None and (now - self._t0) >= self.fault_at:
                    self.inject_fault()
                earliest = min(self._next_due.values()) if self._next_due else now
                if earliest > now:
                    time.sleep(min(earliest - now, 0.002))
                    continue
                for aid, due in list(self._next_due.items()):
                    if now >= due and not self._stop.is_set():
                        self._send_periodic(aid)
                        self._next_due[aid] = due + self._schedule.get(aid, 0.1)
            except Exception:
                time.sleep(0.002)

    def inject_fault(self) -> None:
        """Apply the deterministic fault set once (counter skip, period collapse,
        DLC change, frozen payload, unexpected new ID)."""
        with self._lock:
            if self.faulted:
                return
            self.faulted = True
        self._engine_skip_pending = True
        self._schedule[0x180] = 0.006         # period collapse 20 ms -> 6 ms
        self._body_dlc4 = True                # DLC change 8 -> 4
        self._brake_frozen = self._brake_payload(self._ticks[0x1F0])  # payload freezes
        self._schedule[0x6A0] = 0.050         # previously unseen ID appears
        self._next_due[0x6A0] = time.monotonic()

    def _send_periodic(self, aid: int) -> None:
        tick = self._ticks.get(aid, 0)
        self._ticks[aid] = tick + 1
        counter = self._counters.get(aid, 0)
        extended = aid == 0x18FEF100
        if aid == 0x100:
            if self._engine_skip_pending:
                counter = (counter + 7) & 0xFF   # counter discontinuity
                self._engine_skip_pending = False
                self._counters[aid] = counter
            data = self._engine_payload(counter)
        elif aid == 0x180:
            data = self._transmission_payload(counter)
        elif aid == 0x1F0:
            data = self._brake_frozen if self._brake_frozen is not None else self._brake_payload(tick)
        elif aid == 0x2A0:
            data = bytes([0x01, 0x00, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00])
            if self._body_dlc4:
                data = data[:4]
        elif aid == 0x18FEF100:
            data = bytes([counter & 0xFF, 0x7D, 0x00, 0xFA, 0xFF, 0xFF, 0xFF, 0xFF])
        elif aid == 0x6A0:
            data = bytes([0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        else:
            return
        if aid in self._counters and aid != 0x6A0:
            self._counters[aid] = (counter + 1) & 0xFF
        msg = Message(arbitration_id=aid, is_extended_id=extended, data=bytes(data), is_fd=False)  # type: ignore[misc]
        self._tx_bus.send(msg)
        self.tx_frames += 1

    @staticmethod
    def _engine_payload(counter: int) -> bytes:
        data = bytearray(8)
        data[0] = counter & 0xFF
        data[1] = (counter * 3) & 0xFF          # ramp signal
        data[2] = (counter // 8) & 0xFF         # rpm high byte, slow
        data[3] = 0x5A                          # coolant raw
        data[4] = 0x00
        data[5] = 0x1F
        data[6] = 0x40
        data[7] = _crc8(bytes(data[:7]))
        return bytes(data)

    @staticmethod
    def _transmission_payload(counter: int) -> bytes:
        data = bytearray(8)
        data[0] = counter & 0xFF
        data[1] = 0x02 + (0 if (counter // 64) % 2 == 0 else 1)
        data[2] = (counter // 16) & 0xFF
        data[3] = 0x08
        data[4] = 0x00
        data[5] = 0x00
        data[6] = 0x00
        data[7] = _crc8(bytes(data[:7]))
        return bytes(data)

    @staticmethod
    def _brake_payload(tick: int) -> bytes:
        pressure = 200 + int(400 * abs(math.sin(tick / 17.0)))
        return bytes([pressure & 0xFF, (pressure >> 8) & 0xFF, (tick * 7) % 251,
                      0x00, 0x32, 0x00, 0x00, 0x64])

    # ----------------------------------------------------------- UDS thread --
    def _uds_loop(self) -> None:
        while not self._stop.is_set():
            try:
                msg = self._uds_bus.recv(timeout=0.02)
            except Exception:
                time.sleep(0.01)
                continue
            if msg is None:
                continue
            if int(msg.arbitration_id) != UDS_REQ_ID:
                continue
            data = bytes(msg.data or b"")
            if not data:
                continue
            pci = data[0] >> 4
            if pci != 0:            # flow-control / consecutive frames are not requests
                continue
            length = data[0] & 0x0F
            request = data[1:1 + length]
            if not request:
                continue
            self.uds_requests += 1
            try:
                response = self.handle_uds(request)
            except Exception:
                response = None
            if response:
                try:
                    self._send_isotp(response)
                except Exception:
                    pass

    def _wait_flow_control(self, timeout: float = 0.25) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = self._uds_bus.recv(timeout=max(0.01, deadline - time.time()))
            except Exception:
                return False
            if msg is None:
                return False
            if int(msg.arbitration_id) != UDS_REQ_ID:
                continue
            data = bytes(msg.data or b"")
            if data and (data[0] >> 4) == 3:
                return True
        return False

    def _send_isotp(self, payload: bytes) -> None:
        n = len(payload)
        bus = self._uds_bus
        if n <= 7:
            frame = bytes([n]) + payload + bytes(7 - n)
            bus.send(Message(arbitration_id=UDS_RESP_ID, is_extended_id=False, data=frame))  # type: ignore[misc]
            return
        first = bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6]
        bus.send(Message(arbitration_id=UDS_RESP_ID, is_extended_id=False, data=first))  # type: ignore[misc]
        self._wait_flow_control()
        pos = 6
        seq = 1
        while pos < n:
            chunk = payload[pos:pos + 7]
            frame = bytes([0x20 | (seq & 0x0F)]) + chunk + bytes(7 - len(chunk))
            bus.send(Message(arbitration_id=UDS_RESP_ID, is_extended_id=False, data=frame))  # type: ignore[misc]
            pos += 7
            seq = (seq + 1) & 0x0F
            time.sleep(0.001)

    def _next_seed(self) -> bytes:
        self._seed_serial += 1
        state = (self._seed_base + self._seed_serial * 0x2545F491) & 0xFFFFFFFF
        if state == 0:
            state = 0x0000BEEF
        self._seed = state.to_bytes(4, "big")
        return self._seed

    def expected_key(self, seed: bytes) -> bytes:
        value = int.from_bytes(seed, "big")
        key = (value * self.SEED_KEY_MUL + self.SEED_KEY_ADD) & 0xFFFFFFFF
        return key.to_bytes(4, "big")

    def handle_uds(self, request: bytes) -> bytes | None:
        sid = request[0]
        if sid == 0x10:  # DiagnosticSessionControl
            sub = request[1] if len(request) > 1 else 0
            if sub in (0x01, 0x02):
                self._session, self._unlocked, self._attempts = 1, False, 0
                return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])
            if sub == 0x03:
                self._session, self._unlocked, self._attempts = 3, False, 0
                return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])
            return bytes([0x7F, 0x10, 0x12])
        if sid == 0x3E:  # TesterPresent
            return bytes([0x7E, request[1] if len(request) > 1 else 0x00])
        if sid == 0x22:  # ReadDataByIdentifier
            if len(request) < 3:
                return bytes([0x7F, 0x22, 0x13])
            did = (request[1] << 8) | request[2]
            if did == 0xF190:
                return bytes([0x62, 0xF1, 0x90]) + self.VIN
            if did == 0xF191:
                return bytes([0x62, 0xF1, 0x91]) + self.HW_NUMBER
            if did == 0xF123:              # protected DID
                if not self._unlocked:
                    return bytes([0x7F, 0x22, 0x33])   # securityAccessDenied
                return bytes([0x62, 0xF1, 0x23]) + self.PROTECTED_PAYLOAD
            return bytes([0x7F, 0x22, 0x31])           # requestOutOfRange
        if sid == 0x27:  # SecurityAccess
            sub = request[1] if len(request) > 1 else 0
            if sub == 0x01:                            # requestSeed
                if self._attempts >= self.MAX_ATTEMPTS:
                    return bytes([0x7F, 0x27, 0x36])   # exceededNumberOfAttempts
                return bytes([0x67, 0x01]) + self._next_seed()
            if sub == 0x02:                            # sendKey
                if self._attempts >= self.MAX_ATTEMPTS:
                    return bytes([0x7F, 0x27, 0x36])
                key = request[2:6]
                if len(key) != 4:
                    return bytes([0x7F, 0x27, 0x13])
                if key == self.expected_key(self._seed):
                    self._unlocked = True
                    self._attempts = 0
                    return bytes([0x67, 0x02])
                self._attempts += 1
                return bytes([0x7F, 0x27, 0x35])       # invalidKey
            return bytes([0x7F, 0x27, 0x12])
        return bytes([0x7F, sid, 0x11])                # serviceNotSupported


# ============================================================== lab session ==
class _LabSession:
    """Owns the simulator, the separate reader/witness/replay buses and the
    hand-rolled ISO-TP client used by CAN-07/CAN-08."""

    def __init__(self, channel: str, capture_seconds: float) -> None:
        self.channel = channel
        self.capture_seconds = capture_seconds
        self.sim = VirtualVehicle(channel, fault_at=capture_seconds * 0.6)
        self.sim.start()
        time.sleep(0.15)  # let the ECUs come alive before a reader exists
        # The virtual bus has no self-receive: the reader MUST be its own bus.
        self.reader = Bus(interface="virtual", channel=channel)       # type: ignore[misc]
        self.witness = Bus(interface="virtual", channel=channel)      # type: ignore[misc]
        self.replayer = Bus(interface="virtual", channel=channel)     # type: ignore[misc]
        self.uds_log: list[dict] = []

    # ---------------------------------------------------------------- capture --
    def capture(self) -> tuple[list[dict], float, float]:
        frames: list[dict] = []
        start = time.time()
        end = start + self.capture_seconds
        while time.time() < end and len(frames) < MAX_FRAMES:
            msg = self.reader.recv(timeout=0.05)
            if msg is None:
                continue
            data = bytes(msg.data or b"")
            frames.append({
                "ts": float(msg.timestamp or time.time()),
                "aid": int(msg.arbitration_id),
                "ext": bool(msg.is_extended_id),
                "dlc": int(msg.dlc if msg.dlc is not None else len(data)),
                "data": data,
                "remote": bool(msg.is_remote_frame),
                "error": bool(msg.is_error_frame),
            })
        return frames, start, time.time()

    def drain(self, bus) -> int:
        n = 0
        while bus.recv(timeout=0) is not None:
            n += 1
            if n > 5000:
                break
        return n

    # ------------------------------------------------------------ replay side --
    def replay(self, aid: int, data: bytes, extended: bool, count: int = 2,
               wait: float = 0.6) -> dict:
        """Pause the vehicle (when one is being simulated), transmit the captured frame
        from a *third* socket and count what an independent reader socket actually
        receives."""
        vehicle = getattr(self.sim, "pause_vehicle", None)
        if vehicle:
            vehicle()
        try:
            time.sleep(0.02)
            self.drain(self.witness)
            for _ in range(count):
                self.replayer.send(Message(arbitration_id=aid, is_extended_id=extended,
                                           data=bytes(data), is_fd=False))  # type: ignore[misc]
            observed = []
            deadline = time.time() + wait
            while time.time() < deadline:
                msg = self.witness.recv(timeout=max(0.01, deadline - time.time()))
                if msg is None:
                    continue
                got = bytes(msg.data or b"")
                if int(msg.arbitration_id) == aid and got == bytes(data):
                    observed.append({"ts": round(float(msg.timestamp), 6), "data": _hex(got)})
        finally:
            resume = getattr(self.sim, "resume_vehicle", None)
            if resume:
                resume()
        return {"attempted": count, "observed": len(observed), "frames": observed[:6]}

    # ---------------------------------------------------------------- UDS side --
    def uds_request(self, request: bytes, timeout: float = 0.45) -> dict:
        entry: dict[str, Any] = {"request": _hex(request)}
        if len(request) > 7:
            entry["error"] = "request longer than 7 bytes not used by this engine"
            self.uds_log.append(entry)
            return entry
        frame = bytes([len(request)]) + request + bytes(7 - len(request))
        self.reader.send(Message(arbitration_id=UDS_REQ_ID, is_extended_id=False, data=frame))  # type: ignore[misc]
        raw: list[str] = []
        response: bytes | None = None
        buffer = bytearray()
        expected: int | None = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.reader.recv(timeout=max(0.01, deadline - time.time()))
            if msg is None:
                continue
            if int(msg.arbitration_id) != UDS_RESP_ID:
                continue
            data = bytes(msg.data or b"")
            if not data:
                continue
            raw.append(_hex(data))
            pci = data[0] >> 4
            if pci == 0:
                length = data[0] & 0x0F
                response = data[1:1 + length]
                break
            if pci == 1:
                expected = ((data[0] & 0x0F) << 8) | data[1]
                buffer = bytearray(data[2:8])
                self.reader.send(Message(arbitration_id=UDS_REQ_ID, is_extended_id=False,
                                         data=bytes([0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])))  # type: ignore[misc]
                continue
            if pci == 2 and expected is not None:
                buffer += data[1:8]
                if len(buffer) >= expected:
                    response = bytes(buffer[:expected])
                    break
        entry["raw_frames"] = raw
        entry["response"] = _hex(response) if response else None
        if response:
            entry["positive"] = response[0] != 0x7F
            entry["nrc"] = (f"0x{response[2]:02X}"
                            if response[0] == 0x7F and len(response) > 2 else None)
            entry["service"] = f"0x{response[0]:02X}"
            entry["payload_ascii"] = "".join(
                chr(b) if 32 <= b < 127 else "." for b in response)
        else:
            entry["positive"] = False
            entry["timeout"] = True
        self.uds_log.append(entry)
        return entry

    def shutdown(self) -> None:
        try:
            self.sim.stop()
        except Exception:
            pass
        for bus in (self.reader, self.witness, self.replayer):
            try:
                bus.shutdown()
            except Exception:
                pass

    def stats(self) -> dict:
        return {"channel": self.channel, "tx_frames": self.sim.tx_frames,
                "uds_requests_handled": self.sim.uds_requests,
                "fault_injected": self.sim.faulted,
                "fault_at_s": round(self.sim.fault_at or 0.0, 3)}


# ================================================================== engine ===
class CANEngine:
    module = "automotive_can"
    title = "Module D - Automotive / CAN Bus Pentest"
    description = ("CAN interface discovery, real frame inventory, timing and anomaly "
                   "analysis, replay testing, UDS/ISO-TP diagnostics and security-access review.")
    checks = [
        ("CAN-01", "CAN asset discovery", True),
        ("CAN-02", "CAN ID inventory", True),
        ("CAN-03", "Message classification", True),
        ("CAN-04", "Frequency / timing analysis", True),
        ("CAN-05", "Anomaly detection", True),
        ("CAN-06", "Replay-risk assessment", True),
        ("CAN-07", "ECU communication inventory (UDS/ISO-TP)", True),
        ("CAN-08", "Diagnostic security assessment", True),
        ("CAN-09", "Traffic visualisation data", True),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        source = "lab" if ctx.mode == "lab" else "live"
        state: dict[str, Any] = {
            "source": source, "mode": ctx.mode, "channel": None, "session": None,
            "error": "", "frames": [], "ids": {}, "analysis": {}, "capture_start": 0.0,
            "capture_end": 0.0, "capture_seconds": 3.0, "sim_inventory": [],
            "live_ifaces": [], "replay": {}, "uds": {},
        }
        steps = [
            ("CAN-01", self.asset_discovery),
            ("CAN-02", self.id_inventory),
            ("CAN-03", self.classification),
            ("CAN-04", self.timing_analysis),
            ("CAN-05", self.anomaly_detection),
            ("CAN-06", self.replay_assessment),
            ("CAN-07", self.ecu_inventory),
            ("CAN-08", self.security_assessment),
            ("CAN-09", self.visualisation),
        ]
        try:
            self._prepare(ctx, state)
            for i, (cid, fn) in enumerate(steps):
                if runner.executor.stopped():
                    ctx.add(Result("CAN-STOP", "Execution halted by emergency stop", "error",
                                   description="Remaining automotive checks were not executed.",
                                   source=state["source"]))
                    break
                try:
                    fn(ctx, state)
                except Exception as exc:  # one bad check must not lose the rest
                    ctx.add(Result(cid, f"{cid} raised an exception", "error",
                                   description=f"{type(exc).__name__}: {exc}",
                                   asset=state.get("channel") or "", source=state["source"]))
                ctx.progress(int((i + 1) / len(steps) * 100))
        finally:
            session = state.get("session")
            if session is not None:
                try:
                    session.shutdown()
                except Exception:
                    pass
        return ctx.findings

    # -------------------------------------------------------------- prepare --
    def _prepare(self, ctx: Context, state: dict) -> None:
        if can is None:
            state["error"] = f"python-can is not importable ({CAN_IMPORT_ERROR})"
            return
        channel = target_channel(ctx.targets) or str(ctx.params.get("channel") or "")
        seconds = float(ctx.params.get("capture_seconds", 3) or 3)
        seconds = max(1.0, min(10.0, seconds))
        state["capture_seconds"] = seconds

        if ctx.mode == "lab":
            channel = channel or "wdcan0"
            state["channel"] = channel
            session = _LabSession(channel, seconds)
            state["session"] = session
            state["sim_inventory"] = session.sim.inventory()
            frames, start, end = session.capture()
            state["frames"], state["capture_start"], state["capture_end"] = frames, start, end
            state["ids"] = group_by_id(frames)
            state["analysis"] = analyse_ids(state["ids"])
            return

        # live mode -------------------------------------------------------
        ifaces = socketcan_interfaces()
        state["live_ifaces"] = ifaces
        names = [i["name"] for i in ifaces]
        if not channel or channel not in names:
            channel = names[0] if names else ""
        if not channel:
            state["error"] = ("no SocketCAN interface is present: `ip -details link show` lists "
                              "no CAN device and the kernel has no vcan module loaded")
            return
        state["channel"] = channel
        try:
            reader = Bus(interface="socketcan", channel=channel)          # type: ignore[misc]
            replayer = Bus(interface="socketcan", channel=channel)        # type: ignore[misc]
        except Exception as exc:
            state["error"] = f"SocketCAN open of {channel} failed: {type(exc).__name__}: {exc}"
            return
        session = _LabSession.__new__(_LabSession)      # reuse the ISO-TP client only
        session.channel = channel
        session.reader, session.witness, session.replayer = reader, reader, replayer
        session.uds_log = []
        session.sim = None
        session.capture_seconds = seconds
        state["session"] = session
        frames, start, end = _capture_live(reader, seconds)
        state["frames"], state["capture_start"], state["capture_end"] = frames, start, end
        state["ids"] = group_by_id(frames)
        state["analysis"] = analyse_ids(state["ids"])

    # -------------------------------------------------------------- CAN-01 ---
    def asset_discovery(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        ip_res = runner.run(["ip", "-details", "link", "show"], timeout=10)
        ifaces = parse_ip_link(ip_res.stdout)
        cfgs: list[dict] = []
        cfg_error = ""
        if can is not None:
            try:
                cfgs = can.detect_available_configs(interfaces=["socketcan", "virtual"])
            except Exception as exc:
                cfg_error = f"{type(exc).__name__}: {exc}"
        can_ifaces = [i for i in ifaces if i["can"]]
        evidence: list[dict] = [ip_res.as_evidence(),
                                {"type": "other", "summary": "python-can detected configurations",
                                 "configs": cfgs[:20], "count": len(cfgs),
                                 "error": cfg_error}]
        inventory = state.get("sim_inventory") or []
        if inventory:
            evidence.append({"type": "other", "summary": "simulated vehicle ECU inventory",
                             "inventory": inventory})
        if state["error"]:
            ctx.add(self._unavailable("CAN-01", "CAN asset discovery", state["error"], src,
                                      asset=state.get("channel") or ""))
            return

        if state["mode"] == "lab":
            ecus = ", ".join(f"{r['ecu']}({','.join(r['tx_ids'])}@{r['period_ms']}ms)"
                             for r in inventory)
            desc = (f"Lab bus '{state['channel']}' (python-can virtual, userspace): "
                    f"{len(inventory)} simulated ECUs - {ecus}. "
                    f"Kernel CAN interfaces found: {len(can_ifaces)}"
                    + (f" ({', '.join(i['name'] for i in can_ifaces)})" if can_ifaces else
                       " (none - no vcan/hardware, virtual bus used)")
                    + f"; python-can detected {len(cfgs)} configuration(s).")
        else:
            desc = (f"Live SocketCAN: {len(can_ifaces)} CAN interface(s) "
                    f"({', '.join(i['name'] for i in can_ifaces) or 'none'}) on bus "
                    f"'{state['channel']}'; python-can detected {len(cfgs)} configuration(s).")
        ctx.add(Result("CAN-01", "CAN asset discovery", "info", description=desc,
                       asset=state.get("channel") or "", source=src, evidence=evidence,
                       data={"kernel_interfaces": ifaces, "can_interfaces": can_ifaces,
                             "detected_configs": cfgs[:20], "simulator_ecus": inventory}))

    # -------------------------------------------------------------- CAN-02 ---
    def id_inventory(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        frames = state["frames"]
        if state["error"] or not frames:
            reason = state["error"] or (f"no CAN frame was received on '{state.get('channel')}' "
                                        f"within {state['capture_seconds']}s")
            ctx.add(self._unavailable("CAN-02", "CAN ID inventory", reason, src,
                                      asset=state.get("channel") or ""))
            return
        capture_start = state["capture_start"]
        rows = []
        for aid in sorted(state["ids"]):
            fr = state["ids"][aid]
            deltas = [b["ts"] - a["ts"] for a, b in zip(fr, fr[1:])]
            rows.append({
                "arbitration_id": _aid_hex(aid),
                "extended": fr[0]["ext"],
                "dlc": sorted({f["dlc"] for f in fr}),
                "count": len(fr),
                "first_offset_s": round(fr[0]["ts"] - capture_start, 4),
                "last_offset_s": round(fr[-1]["ts"] - capture_start, 4),
                "period_ms": round(statistics.fmean(deltas) * 1000, 2) if deltas else None,
                "payload_sample": _hex(fr[0]["data"]),
            })
        table = "\n".join(
            f"{r['arbitration_id']:>10}  ext={str(r['extended']):5}  dlc={r['dlc']}  n={r['count']:4d}  "
            f"period={r['period_ms']} ms  first={r['first_offset_s']}s  {r['payload_sample']}"
            for r in rows)
        art = ctx.save_text("can_id_inventory.txt",
                            f"CAN ID inventory - channel {state['channel']} "
                            f"(capture {state['capture_seconds']}s, {len(frames)} frames)\n"
                            f"{table}\n")
        raw_art = ctx.save_text("can_capture.json", json.dumps(
            [{"ts": round(f["ts"] - capture_start, 6), "id": _aid_hex(f["aid"]),
              "ext": f["ext"], "dlc": f["dlc"], "data": _hex(f["data"])}
             for f in frames], indent=0))
        ctx.add(Result(
            "CAN-02", "CAN ID inventory", "info",
            description=(f"{len(rows)} distinct arbitration ID(s) observed in {len(frames)} real "
                         f"frame(s) captured over {state['capture_seconds']}s on "
                         f"'{state['channel']}'."),
            asset=state.get("channel") or "", source=src,
            evidence=[{"type": "other", "summary": "per-ID inventory measured from received frames",
                       "ids": rows}, art, raw_art],
            data={"ids": rows, "frame_count": len(frames),
                  "extended_ids": [r["arbitration_id"] for r in rows if r["extended"]],
                  "standard_ids": [r["arbitration_id"] for r in rows if not r["extended"]]}))

    # -------------------------------------------------------------- CAN-03 ---
    def classification(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        analysis = state["analysis"]
        if state["error"] or not analysis:
            ctx.add(self._unavailable("CAN-03", "Message classification",
                                      state["error"] or "no frames captured to classify", src,
                                      asset=state.get("channel") or ""))
            return
        rows = []
        for aid in sorted(analysis):
            a = analysis[aid]
            labels = list(a["labels"])
            rows.append({"arbitration_id": _aid_hex(aid), "count": a["count"],
                         "classes": labels,
                         "counter_byte": a["counter"]["byte"] if a["counter"] else None,
                         "counter_increment_ratio": (round(a["counter"]["ratio"], 3)
                                                     if a["counter"] else None),
                         "checksum_byte": (a["checksum"][0]["byte"] if a["checksum"] else None),
                         "checksum_basis": "heuristic: byte value determined by the counter byte",
                         "jitter_cv": a["timing"].get("jitter_cv")})
        table = "\n".join(f"{r['arbitration_id']:>10}  n={r['count']:4d}  {', '.join(r['classes'])}"
                          f"  counter_byte={r['counter_byte']}  checksum_byte={r['checksum_byte']}"
                          for r in rows)
        art = ctx.save_text("can_classification.txt",
                            "Message classification (measured from captured frames)\n" + table + "\n")
        periodic = [r["arbitration_id"] for r in rows if "periodic" in r["classes"]]
        bursty = [r["arbitration_id"] for r in rows if "event/bursty" in r["classes"]]
        counters = [r["arbitration_id"] for r in rows if r["counter_byte"] is not None]
        checksums = [r["arbitration_id"] for r in rows if r["checksum_byte"] is not None]
        analog = [r["arbitration_id"] for r in rows if any(c.startswith("signal") for c in r["classes"])]
        ctx.add(Result(
            "CAN-03", "Message classification", "info",
            description=(f"{len(periodic)} periodic, {len(bursty)} event/bursty, "
                         f"{len(counters)} counter-bearing, {len(checksums)} checksum-bearing "
                         f"(heuristic), {len(analog)} signal-bearing ID(s) measured. "
                         f"Thresholds: periodic = inter-arrival CV <= 0.25; counter = byte "
                         f"incrementing by +1 (mod 256) in >= 80% of transitions; checksum = "
                         f"heuristic byte that changes on >= 90% of frames and is a deterministic "
                         f"function of the counter byte."),
            asset=state.get("channel") or "", source=src,
            evidence=[{"type": "other", "summary": "per-ID classification", "classes": rows}, art],
            data={"classes": rows, "periodic": periodic, "bursty": bursty,
                  "counter_bearing": counters, "checksum_bearing_heuristic": checksums,
                  "signal_bearing": analog}))

    # -------------------------------------------------------------- CAN-04 ---
    def timing_analysis(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        analysis = state["analysis"]
        if state["error"] or not analysis:
            ctx.add(self._unavailable("CAN-04", "Frequency / timing analysis",
                                      state["error"] or "no frames captured for timing analysis",
                                      src, asset=state.get("channel") or ""))
            return
        rows = []
        flags = []
        for aid in sorted(analysis):
            a = analysis[aid]
            t = a["timing"]
            if t.get("samples", 0) < MIN_FRAMES_TIMING - 1:
                continue
            row = {"arbitration_id": _aid_hex(aid), **t}
            rows.append(row)
            if t.get("jitter_cv") is not None and t["jitter_cv"] > JITTER_CV_FLAG:
                flags.append(f"{_aid_hex(aid)} inter-arrival CV {t['jitter_cv']} > {JITTER_CV_FLAG}")
        table = "\n".join(
            f"{r['arbitration_id']:>10}  mean={r['mean_ms']:8.3f} ms  stdev={r['stdev_ms']:7.3f}  "
            f"min={r['min_ms']:7.3f}  max={r['max_ms']:8.3f}  jitter(cv)={r['jitter_cv']:.3f}"
            for r in rows) or "(not enough frames per ID)"
        art = ctx.save_text("can_timing.txt",
                            "Inter-arrival statistics per arbitration ID (measured)\n" + table + "\n")
        ctx.add(Result(
            "CAN-04", "Frequency / timing analysis", "info",
            description=(f"Measured inter-arrival statistics for {len(rows)} ID(s) with >= "
                         f"{MIN_FRAMES_TIMING - 1} intervals; "
                         f"{len(flags)} ID(s) exceed the jitter threshold CV > {JITTER_CV_FLAG}"
                         + (": " + "; ".join(flags) if flags else "") + "."),
            asset=state.get("channel") or "", source=src,
            evidence=[{"type": "other", "summary": "timing statistics per ID", "timing": rows}, art],
            data={"timing": rows, "jitter_flags": flags}))

    # -------------------------------------------------------------- CAN-05 ---
    def anomaly_detection(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        if state["error"] or not state["frames"]:
            ctx.add(self._unavailable("CAN-05", "Anomaly detection",
                                      state["error"] or "no frames captured to analyse", src,
                                      asset=state.get("channel") or ""))
            return
        anomalies = detect_anomalies(state["ids"], state["capture_start"],
                                     state["capture_end"], state["analysis"])
        art = ctx.save_text("can_anomalies.json", json.dumps(anomalies, indent=2))
        if not anomalies:
            ctx.add(Result(
                "CAN-05", "Anomaly detection", "pass",
                description=(f"No anomaly of the measured classes was observed across "
                             f"{len(state['frames'])} frames. Thresholds: late ID = first seen "
                             f"> {int(LATE_ID_REL * 100)}% into the window; DLC change = > 1 DLC "
                             f"for one ID; period deviation = split-half mean change > "
                             f"{int(PERIOD_DEVIATION_RATIO * 100)}%; counter discontinuity = "
                             f"delta > 1 (mod 256); frozen payload = >= {FROZEN_RUN} identical "
                             f"consecutive payloads."),
                asset=state.get("channel") or "", source=src,
                evidence=[{"type": "other", "summary": "no anomaly detected"}, art],
                data={"anomalies": []}))
            return
        severity = {"counter_discontinuity": "medium", "period_deviation": "medium",
                    "dlc_change": "low", "late_id": "low", "payload_frozen": "low"}
        by_class: dict[str, list[dict]] = {}
        for item in anomalies:
            by_class.setdefault(item["class"], []).append(item)
        first = True
        for cls in ("counter_discontinuity", "period_deviation", "dlc_change",
                    "payload_frozen", "late_id"):
            items = by_class.get(cls)
            if not items:
                continue
            detail = " | ".join(f"{_aid_hex(i['aid'])}: {i['detail']}" for i in items[:6])
            frames_ev = [fr for i in items[:4] for fr in i["frames"][:4]]
            ctx.add(Result(
                "CAN-05", f"Anomaly detected - {cls.replace('_', ' ')}", "fail",
                severity=severity.get(cls, "low"),
                description=(f"{len(items)} {cls.replace('_', ' ')} anomaly(ies) measured in the "
                             f"captured traffic ({detail})."),
                asset=state.get("channel") or "", source=src,
                cvss_score=5.3 if severity.get(cls) == "medium" else 3.1,
                cvss_vector=("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
                             if severity.get(cls) == "medium"
                             else "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
                cwe=["CWE-345"],
                remediation=("Monitor CAN traffic against a per-ID timing/payload baseline and "
                             "alert on counter, period, DLC and payload deviations at the gateway."),
                evidence=[{"type": "other", "summary": f"{cls} anomalies",
                           "anomalies": items[:8], "evidencing_frames": frames_ev[:10]},
                          art if first else {"type": "other", "summary": "see can_anomalies.json",
                                             "path": art["path"]}],
                data={"class": cls, "anomalies": items[:8],
                      "thresholds": {"late_id_rel": LATE_ID_REL,
                                     "period_deviation_ratio": PERIOD_DEVIATION_RATIO,
                                     "jitter_cv": JITTER_CV_FLAG,
                                     "frozen_run": FROZEN_RUN}}))
            first = False

    # -------------------------------------------------------------- CAN-06 ---
    def replay_assessment(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        if state["error"] or not state["frames"]:
            ctx.add(self._unavailable("CAN-06", "Replay-risk assessment",
                                      state["error"] or "no frames captured to replay", src,
                                      asset=state.get("channel") or ""))
            return
        session = state["session"]
        analysis = state["analysis"]  # frames comes from the enclosing capture scope
        # decide from measurement: static payload + no counter/checksum == replay friendly
        decisions = []
        for aid in sorted(state["ids"]):
            fr = state["ids"][aid]
            a = analysis.get(aid, {})
            distinct = len({f["data"] for f in fr})
            has_counter = bool(a.get("counter"))
            has_checksum = bool(a.get("checksum"))
            friendly = not has_counter and not has_checksum
            if not friendly:
                verdict = ("replay resistant - a rolling counter and/or checksum must be "
                           "regenerated and stay in sequence")
            elif distinct == 1:
                verdict = "replay friendly - static payload, no freshness field"
            else:
                verdict = ("replay friendly - no counter or checksum, so nothing binds a frame "
                           "to a sequence (payload varies, the sequence does not)")
            decisions.append({"arbitration_id": _aid_hex(aid), "distinct_payloads": distinct,
                              "rolling_counter": has_counter, "checksum_like_byte": has_checksum,
                              "verdict": verdict})
        static_rows = [d for d in decisions if d["verdict"].startswith("replay friendly")]
        dynamic_rows = [d for d in decisions if not d["verdict"].startswith("replay friendly")]
        # replay the ID that best demonstrates the risk: present from the start of the
        # capture (not an injected/late artefact), most static payload first
        span = max(1e-6, state["capture_end"] - state["capture_start"])
        def _pref(d: dict) -> tuple:
            fr = state["ids"][int(d["arbitration_id"], 16)]
            late = (fr[0]["ts"] - state["capture_start"]) > LATE_ID_REL * span
            return (1 if late else 0, d["distinct_payloads"], int(d["arbitration_id"], 16))
        preferred = sorted(static_rows, key=_pref)
        replay_target = (preferred or [None])[0]
        results = {}
        if session is not None:
            if replay_target:
                aid = int(replay_target["arbitration_id"], 16)
                fr = state["ids"][aid]
                results["static"] = {"arbitration_id": _aid_hex(aid),
                                     "sent_frame": _hex(fr[0]["data"]),
                                     "note": "captured frame re-transmitted verbatim, real ECU "
                                             "traffic paused so only the replay is on the bus",
                                     **session.replay(aid, fr[0]["data"], fr[0]["ext"], count=2)}
            if dynamic_rows:
                aid = int(dynamic_rows[0]["arbitration_id"], 16)
                fr = state["ids"][aid]
                # a late capture of a counter+checksum frame: replay it and show it is stale
                results["dynamic"] = {"arbitration_id": _aid_hex(aid),
                                      "sent_frame": _hex(fr[-1]["data"]),
                                      **session.replay(aid, fr[-1]["data"], fr[-1]["ext"], count=1),
                                      "last_live_counter_byte": fr[-1]["data"][0] if fr[-1]["data"] else None}
        state["replay"] = results
        art = ctx.save_text("can_replay.json", json.dumps(
            {"decisions": decisions, "replay": results}, indent=2))
        performed = [f"{v['arbitration_id']}: {v['observed']}/{v['attempted']} frame(s) received "
                     f"by an independent reader socket" for v in results.values()]
        ctx.add(Result(
            "CAN-06", "Replay-risk assessment", "info",
            description=(f"Replay risk derived from measurement: {len(static_rows)} replay-friendly, "
                         f"{len(dynamic_rows)} replay-resistant ID(s). Lab replay performed: "
                         + ("; ".join(performed) if performed else "not performed") + "."),
            asset=state.get("channel") or "", source=src,
            evidence=[{"type": "other", "summary": "replay decisions and outcome",
                       "decisions": decisions, "replay": results}, art],
            data={"decisions": decisions, "replay": results}))
        if static_rows:
            ids = ", ".join(d["arbitration_id"] for d in static_rows)
            proven = results.get("static") or {}
            proof = (f" {proven.get('arbitration_id')} was re-transmitted verbatim"
                     f" ({proven.get('sent_frame')}) and an independent reader socket received"
                     f" {proven.get('observed')}/{proven.get('attempted')} of the replayed"
                     f" frame(s)." if proven.get("observed") else
                     " The frames were classified as replay-friendly from measurement; "
                     "no replayed frame was confirmed by a reader.")
            fully_static = [d for d in static_rows if d["distinct_payloads"] == 1]
            medium = still_sev_hi(fully_static, proven)
            ctx.add(Result(
                "CAN-06", "Replay-friendly CAN frames accepted", "fail",
                severity="medium" if medium else "low",
                description=(f"{ids} carry no rolling counter and no checksum, so a recorded"
                             f" frame is accepted whenever it is injected.{proof}"),
                asset=state.get("channel") or "", source=src,
                cvss_score=5.9 if medium else 4.2,
                cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                cwe=["CWE-294"],
                remediation=("Add a rolling counter plus message checksum/MAC to these frames and "
                             "validate freshness in the receiving ECU."),
                evidence=[{"type": "other", "summary": "replay-friendly IDs and transmitted frames",
                           "ids": static_rows, "replay": results.get("static", {})}],
                data={"replay_friendly_ids": [d["arbitration_id"] for d in static_rows],
                      "replay": results.get("static", {})}))

    # -------------------------------------------------------------- CAN-07 ---
    def ecu_inventory(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        session = state.get("session")
        if state["error"] or session is None:
            ctx.add(self._unavailable("CAN-07", "ECU communication inventory (UDS/ISO-TP)",
                                      state["error"] or "no CAN bus session", src,
                                      asset=state.get("channel") or ""))
            return
        if getattr(session, "sim", None) is None and state["mode"] == "lab":
            ctx.add(self._unavailable("CAN-07", "ECU communication inventory (UDS/ISO-TP)",
                                      "simulator unavailable", src,
                                      asset=state.get("channel") or ""))
            return
        exchanges: list[dict] = []
        default_session = session.uds_request(bytes([0x10, 0x01]))
        exchanges.append({**default_session, "label": "0x10 01 default session"})
        extended = session.uds_request(bytes([0x10, 0x03]))
        exchanges.append({**extended, "label": "0x10 03 extended session"})
        vin = session.uds_request(bytes([0x22, 0xF1, 0x90]))
        exchanges.append({**vin, "label": "0x22 F190 VIN"})
        hw = session.uds_request(bytes([0x22, 0xF1, 0x91]))
        exchanges.append({**hw, "label": "0x22 F191 hardware number"})
        tester = session.uds_request(bytes([0x3E, 0x00]))
        exchanges.append({**tester, "label": "0x3E 00 TesterPresent"})
        state["uds"]["inventory"] = exchanges

        vin_text = decode_ascii(vin.get("response"), skip=3)
        hw_text = decode_ascii(hw.get("response"), skip=3)
        answered = [e for e in exchanges if e.get("response")]
        art = ctx.save_text("can_uds_inventory.txt", format_uds_log(exchanges))
        ctx.add(Result(
            "CAN-07", "ECU communication inventory (UDS/ISO-TP)", "info",
            description=(f"{len(answered)}/{len(exchanges)} UDS request(s) answered on "
                         f"0x{UDS_REQ_ID:X} -> 0x{UDS_RESP_ID:X} over a hand-built ISO-TP "
                         f"transport (single + first/consecutive frames). "
                         f"VIN='{vin_text}' hardware='{hw_text}'; tester present "
                         f"{'acknowledged' if tester.get('response') else 'not acknowledged'}."),
            asset=state.get("channel") or "", source=src,
            evidence=[{"type": "other", "summary": "UDS/ISO-TP exchanges (raw frames)",
                       "exchanges": exchanges}, art],
            data={"exchanges": exchanges, "vin": vin_text, "hardware_number": hw_text,
                  "request_id": _aid_hex(UDS_REQ_ID), "response_id": _aid_hex(UDS_RESP_ID),
                  "transport": "ISO-TP (ISO 15765-2) over python-can, assembled in-process"}))
        state["uds"]["vin"] = vin_text
        state["uds"]["hw"] = hw_text

    # -------------------------------------------------------------- CAN-08 ---
    def security_assessment(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        session = state.get("session")
        if state["error"] or session is None or not state.get("uds", {}).get("inventory"):
            ctx.add(self._unavailable("CAN-08", "Diagnostic security assessment",
                                      state["error"] or "UDS responder did not answer CAN-07", src,
                                      asset=state.get("channel") or ""))
            return
        steps: list[dict] = []
        session.uds_request(bytes([0x10, 0x03]))          # extended session, locked
        before = session.uds_request(bytes([0x22, 0xF1, 0x23]))
        steps.append({**before, "label": "protected 0x22 F123 before SecurityAccess"})
        access_required = before.get("nrc") == "0x33"

        # behavioural inference of the seed -> key algorithm
        candidates: list[tuple[str, Any]] = [
            ("identity (key = seed)", lambda s: s),
            ("xor 0x5A5A5A5A", lambda s: s ^ 0x5A5A5A5A),
            ("seed * 0x1234 + 0xABCD (mod 2^32)", lambda s: (s * 0x1234 + 0xABCD) & 0xFFFFFFFF),
            ("seed + 0x1234 (mod 2^32)", lambda s: (s + 0x1234) & 0xFFFFFFFF),
            ("bitwise not (mod 2^32)", lambda s: (~s) & 0xFFFFFFFF),
        ]
        seed_req = session.uds_request(bytes([0x27, 0x01]))
        steps.append({**seed_req, "label": "0x27 01 requestSeed #1"})
        seed_hex = seed_requested(seed_req)
        accepted = None
        attempts_used = 0
        if seed_hex:
            seed_int = int(seed_hex, 16)
            for label, fn in candidates:
                key = fn(seed_int) & 0xFFFFFFFF
                attempt = session.uds_request(bytes([0x27, 0x02]) + key.to_bytes(4, "big"))
                attempts_used += 1
                steps.append({**attempt, "label": f"0x27 02 sendKey candidate '{label}'",
                              "candidate_key": f"{key:08X}"})
                if attempt.get("positive"):
                    accepted = label
                    break
        # verify the inferred formula against a second, different seed
        verify: dict = {}
        if accepted:
            seed2_req = session.uds_request(bytes([0x27, 0x01]))
            steps.append({**seed2_req, "label": "0x27 01 requestSeed #2 (verification)"})
            seed2 = seed_requested(seed2_req)
            if seed2:
                fn = dict(candidates)[accepted]
                key2 = fn(int(seed2, 16)) & 0xFFFFFFFF
                verify = session.uds_request(bytes([0x27, 0x02]) + key2.to_bytes(4, "big"))
                steps.append({**verify, "label": "0x27 02 sendKey predicted for seed #2",
                              "candidate_key": f"{key2:08X}"})
        after = session.uds_request(bytes([0x22, 0xF1, 0x23]))
        steps.append({**after, "label": "protected 0x22 F123 after SecurityAccess"})
        protected_ascii = decode_ascii(after.get("response"), skip=3)

        # does security access survive a session change?
        session.uds_request(bytes([0x10, 0x01]))
        session.uds_request(bytes([0x10, 0x03]))
        reset = session.uds_request(bytes([0x22, 0xF1, 0x23]))
        steps.append({**reset, "label": "protected 0x22 F123 after session reset"})
        unlock_persists = reset.get("positive", False)

        # measured attempt limit (deliberately wrong keys until the ECU locks out)
        session.uds_request(bytes([0x27, 0x01]))
        wrong = b"\xDE\xAD\xBE\xEF"
        lockout_after = None
        rejected_keys = 0
        for i in range(1, 9):
            r = session.uds_request(bytes([0x27, 0x02]) + wrong)
            steps.append({**r, "label": f"wrong key attempt {i}"})
            if r.get("nrc") == "0x36":
                lockout_after = i
                break
            if r.get("nrc") == "0x35":
                rejected_keys += 1
            session.uds_request(bytes([0x27, 0x01]))  # re-arm seed

        art = ctx.save_text("can_security_access.txt", format_uds_log(steps))
        observed = {
            "protected_did": "0xF123",
            "security_access_required": access_required,
            "denial_nrc": before.get("nrc"),
            "seed": seed_hex,
            "seed_bytes": len(seed_hex) // 2 if seed_hex else 0,
            "accepted_algorithm": accepted,
            "candidate_attempts_used": attempts_used,
            "verified_on_second_seed": bool(verify.get("positive")),
            "protected_read_before_unlock": before.get("response"),
            "protected_read_after_unlock": after.get("response"),
            "protected_payload_ascii": protected_ascii,
            "unlock_survives_session_change": unlock_persists,
            "wrong_keys_rejected": rejected_keys,
            "lockout_at_attempt": lockout_after,
        }
        state["uds"]["security"] = observed
        if access_required and accepted:
            ctx.add(Result(
                "CAN-08", "Diagnostic security access is bypassable (weak seed/key)", "fail",
                severity="medium",
                description=(f"Protected DID 0xF123 refused with NRC {before.get('nrc')} "
                             f"(securityAccessDenied) until SecurityAccess; a {observed['seed_bytes']}-"
                             f"byte seed was issued (0x{seed_hex}) and the key algorithm was "
                             f"inferred behaviourally as '{accepted}' in {attempts_used} attempt(s), "
                             f"then predicted correctly for a second seed "
                             f"({'confirmed' if verify.get('positive') else 'not confirmed'}). "
                             f"Observed on the simulator, not a production ECU. Attempt limiting: "
                             f"{rejected_keys} wrong key(s) rejected with NRC 0x35, then NRC 0x36 "
                             f"(exceededNumberOfAttempts) on attempt {lockout_after}. "
                             f"Unlock persists across a session change: {unlock_persists}."),
                asset=state.get("channel") or "", source=src, cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                cwe=["CWE-287", "CWE-330"],
                remediation=("Use a per-ECU secret key with a cryptographic seed/key exchange, "
                             "rate-limit seed requests and lock out after a few invalid keys."),
                evidence=[{"type": "other", "summary": "SecurityAccess observations",
                           "observed": observed}, art],
                data=observed))
        else:
            ctx.add(Result(
                "CAN-08", "Diagnostic security assessment", "info",
                description=(f"SecurityAccess {'was required' if access_required else 'was not required'} "
                             f"for the protected DID; key algorithm "
                             f"{'inferred as ' + accepted if accepted else 'not inferred'}. "
                             f"Protected payload: {protected_ascii!r}."),
                asset=state.get("channel") or "", source=src,
                evidence=[{"type": "other", "summary": "SecurityAccess observations",
                           "observed": observed}, art],
                data=observed))
        if not access_required:
            ctx.add(Result(
                "CAN-08", "Protected diagnostic operation needs no security access", "fail",
                severity="high",
                description=("The protected DID 0xF123 answered without any SecurityAccess, so "
                             "any tester on the bus can read protected configuration."),
                asset=state.get("channel") or "", source=src, cvss_score=7.1,
                cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe=["CWE-306"],
                remediation="Require SecurityAccess (0x27) before serving protected DIDs.",
                evidence=[{"type": "other", "summary": "unprotected read",
                           "response": before.get("response")}],
                data={"protected_read": before.get("response")}))

    # -------------------------------------------------------------- CAN-09 ---
    def visualisation(self, ctx: Context, state: dict) -> None:
        src = state["source"]
        if state["error"] or not state["frames"]:
            ctx.add(self._unavailable("CAN-09", "Traffic visualisation data",
                                      state["error"] or "no frames captured to visualise", src,
                                      asset=state.get("channel") or ""))
            return
        start, end = state["capture_start"], state["capture_end"]
        span = max(1e-6, end - start)
        bucket_s = 0.25
        buckets = max(1, int(math.ceil(span / bucket_s)))
        counts = {aid: [0] * buckets for aid in state["ids"]}
        for fr in state["frames"]:
            idx = min(buckets - 1, int((fr["ts"] - start) / bucket_s))
            counts[fr["aid"]][idx] += 1
        matrix = {}
        for aid in sorted(state["ids"]):
            a = state["analysis"][aid]
            matrix[_aid_hex(aid)] = {
                "change_rate": [round(x, 3) for x in a["byte_change_rate"]],
                "distinct_values": a["byte_distinct"],
                "counter_byte": a["counter"]["byte"] if a["counter"] else None,
                "checksum_byte": a["checksum"][0]["byte"] if a["checksum"] else None,
            }
        viz = {
            "channel": state["channel"], "source": src,
            "capture_seconds": round(span, 3), "frames": len(state["frames"]),
            "bucket_seconds": bucket_s, "buckets": buckets,
            "per_id_bucket_counts": {_aid_hex(aid): counts[aid] for aid in sorted(counts)},
            "per_id_totals": {_aid_hex(aid): len(state["ids"][aid]) for aid in sorted(state["ids"])},
            "byte_activity_matrix": matrix,
            "period_ms": {r["arbitration_id"]: r["period_ms"] for r in
                          [{"arbitration_id": _aid_hex(a), "period_ms": state["analysis"][a]["timing"].get("mean_ms")}
                           for a in sorted(state["analysis"])]},
        }
        json_art = ctx.save_text("can_traffic_viz.json", json.dumps(viz, indent=2))
        lines = [f"CAN traffic summary - channel {state['channel']} ({src}), "
                 f"{len(state['frames'])} frames in {span:.2f}s",
                 f"timeline buckets: {buckets} x {bucket_s}s", "",
                 f"{'ID':>10} {'total':>6} {'period_ms':>10}  bucket counts",
                 "-" * 96]
        for aid in sorted(state["ids"]):
            row = counts[aid]
            lines.append(f"{_aid_hex(aid):>10} {sum(row):6d} "
                         f"{(state['analysis'][aid]['timing'].get('mean_ms') or 0):10.2f}  "
                         + " ".join(f"{c:>3d}" for c in row))
        lines += ["", "ID x byte activity matrix (change rate over consecutive frames):",
                  f"{'ID':>10} " + " ".join(f"B{i:<5}" for i in range(8))]
        for aid in sorted(state["ids"]):
            m = matrix[_aid_hex(aid)]
            lines.append(f"{_aid_hex(aid):>10} " + " ".join(f"{v:5.2f}" for v in m["change_rate"]))
        text_art = ctx.save_text("can_traffic_viz.txt", "\n".join(lines) + "\n")
        ctx.add(Result(
            "CAN-09", "Traffic visualisation data", "info",
            description=(f"Per-ID timeline ({buckets} buckets of {bucket_s}s) and an ID x byte "
                         f"activity matrix generated for {len(state['ids'])} ID(s) from "
                         f"{len(state['frames'])} measured frames; JSON and text summary saved."),
            asset=state.get("channel") or "", source=src,
            evidence=[json_art, text_art,
                      {"type": "other", "summary": "visualisation summary",
                       "per_id_totals": viz["per_id_totals"], "buckets": buckets}],
            data={"json": json_art["path"], "text": text_art["path"],
                  "per_id_totals": viz["per_id_totals"], "buckets": buckets,
                  "byte_activity_matrix": matrix}))

    # -------------------------------------------------------------- helpers --
    @staticmethod
    def _unavailable(check_id: str, title: str, reason: str, source: str,
                     asset: str = "") -> Result:
        """`unavailable` that keeps the provenance of the mode it ran in."""
        res = unavailable(check_id, title, reason, asset=asset)
        res.source = source
        return res


# ================================================================ analysis ===
def group_by_id(frames: list[dict]) -> dict[int, list[dict]]:
    ids: dict[int, list[dict]] = {}
    for fr in frames:
        ids.setdefault(fr["aid"], []).append(fr)
    return ids


def analyse_ids(ids: dict[int, list[dict]]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for aid, frames in ids.items():
        payloads = [f["data"] for f in frames]
        deltas = [b["ts"] - a["ts"] for a, b in zip(frames, frames[1:])]
        counter = detect_counter(payloads)
        checksums = detect_checksum(payloads, counter["byte"] if counter else None)
        timing = timing_stats(deltas)
        labels: list[str] = []
        if timing.get("samples", 0) >= MIN_FRAMES_TIMING - 1 and timing["jitter_cv"] is not None:
            labels.append("periodic" if timing["jitter_cv"] <= 0.25 else "event/bursty")
        if counter:
            labels.append("counter-bearing")
        if checksums:
            labels.append("checksum-bearing (heuristic)")
        signals = detect_signals(payloads, counter["byte"] if counter else None,
                                 checksums[0]["byte"] if checksums else None)
        if signals:
            labels.extend(sorted({s["kind"] for s in signals}))
        out[aid] = {
            "count": len(frames),
            "counter": counter,
            "checksum": checksums,
            "timing": timing,
            "labels": labels,
            "signals": signals,
            "byte_change_rate": byte_change_rates(payloads),
            "byte_distinct": [len({p[i] for p in payloads if len(p) > i}) for i in range(8)],
        }
    return out


def detect_counter(payloads: list[bytes]) -> dict | None:
    """Byte that advances by exactly +1 (mod 256) in >= 80% of transitions."""
    n = len(payloads)
    if n < 8:
        return None
    best: dict | None = None
    for i in range(8):
        if any(len(p) <= i for p in payloads):
            continue
        ones = sum(1 for a, b in zip(payloads, payloads[1:]) if ((b[i] - a[i]) & 0xFF) == 1)
        ratio = ones / (n - 1)
        if ratio >= 0.80 and (best is None or ratio > best["ratio"]):
            best = {"byte": i, "ratio": ratio, "transitions": n - 1, "increments": ones}
    return best


def detect_checksum(payloads: list[bytes], counter_idx: int | None) -> list[dict]:
    """Heuristic: byte that changes on >= 90% of frames and whose value is fully
    determined by the counter byte for >= 75% of observed counter values (and is
    not itself a simple ramp/counter)."""
    n = len(payloads)
    if n < 8 or counter_idx is None:
        return []
    transitions = n - 1
    candidates: list[dict] = []
    for i in range(8):
        if i == counter_idx or any(len(p) <= i for p in payloads):
            continue
        values = [p[i] for p in payloads]
        changes = sum(1 for a, b in zip(values, values[1:]) if a != b)
        rate = changes / transitions
        if rate < 0.90:
            continue
        distinct = len(set(values))
        if distinct < 16:
            continue
        deltas = {(b - a) & 0xFF for a, b in zip(values, values[1:])}
        if len(deltas) <= 2:          # a second counter / ramp, not a checksum
            continue
        groups: dict[int, set[int]] = {}
        for payload, value in zip(payloads, values):
            groups.setdefault(payload[counter_idx], set()).add(value)
        determinism = sum(1 for s in groups.values() if len(s) == 1) / max(1, len(groups))
        if determinism < 0.75:
            continue
        candidates.append({"byte": i, "change_rate": round(rate, 3),
                           "determinism": round(determinism, 3), "distinct": distinct,
                           "method": "heuristic: value determined by the counter byte"})
    candidates.sort(key=lambda c: (-c["determinism"], -c["change_rate"]))
    return candidates


def byte_change_rates(payloads: list[bytes]) -> list[float]:
    rates = []
    for i in range(8):
        pairs = [(a[i], b[i]) for a, b in zip(payloads, payloads[1:])
                 if len(a) > i and len(b) > i]
        rates.append((sum(1 for a, b in pairs if a != b) / len(pairs)) if pairs else 0.0)
    return rates


def detect_signals(payloads: list[bytes], counter_idx: int | None,
                   checksum_idx: int | None) -> list[dict]:
    """Signal candidates: a byte with several distinct values, or an adjacent
    big-endian 16-bit pair whose low byte moves and whose high byte rarely does."""
    if len(payloads) < 6:
        return []
    rates = byte_change_rates(payloads)
    found: list[dict] = []
    for i in range(8):
        if i in (counter_idx, checksum_idx):
            continue
        values = [p[i] for p in payloads if len(p) > i]
        distinct = len(set(values))
        if distinct >= 6 and rates[i] >= 0.30:
            found.append({"kind": "signal (single-byte analog)", "byte": i,
                          "distinct": distinct, "change_rate": round(rates[i], 3)})
    for i in range(7):
        if i in (counter_idx, checksum_idx) or (i + 1) in (counter_idx, checksum_idx):
            continue
        pairs = [(p[i] << 8) | p[i + 1] for p in payloads if len(p) > i + 1]
        if len(pairs) < 6:
            continue
        distinct = len(set(pairs))
        if distinct >= 6 and rates[i + 1] >= 0.40 and rates[i] <= 0.15:
            found.append({"kind": "signal (multi-byte 16-bit)", "bytes": [i, i + 1],
                          "distinct": distinct, "high_byte_rate": round(rates[i], 3),
                          "low_byte_rate": round(rates[i + 1], 3)})
    return found


def timing_stats(deltas: list[float]) -> dict:
    if not deltas:
        return {"samples": 0}
    ms = [d * 1000 for d in deltas]
    mean = statistics.fmean(ms)
    stdev = statistics.pstdev(ms) if len(ms) > 1 else 0.0
    mad = statistics.fmean([abs(x - mean) for x in ms])
    return {"samples": len(ms), "mean_ms": round(mean, 3), "stdev_ms": round(stdev, 3),
            "min_ms": round(min(ms), 3), "max_ms": round(max(ms), 3),
            "jitter_ms_mad": round(mad, 3),
            "jitter_cv": round(stdev / mean, 3) if mean else None}


def detect_anomalies(ids: dict[int, list[dict]], start: float, end: float,
                     analysis: dict) -> list[dict]:
    span = max(1e-6, end - start)
    anomalies: list[dict] = []
    for aid in sorted(ids):
        frames = ids[aid]
        a = analysis.get(aid, {})
        # 1) ID that only appears part-way through the capture
        rel = (frames[0]["ts"] - start) / span
        if rel > LATE_ID_REL:
            anomalies.append({
                "class": "late_id", "aid": aid,
                "detail": (f"first frame only at {rel * 100:.1f}% of the window "
                           f"({len(frames)} frame(s), previously unseen)"),
                "frames": [{"offset_s": round(f["ts"] - start, 4), "dlc": f["dlc"],
                            "data": _hex(f["data"])} for f in frames[:5]]})
        # 2) DLC change
        dlcs = sorted({f["dlc"] for f in frames})
        if len(dlcs) > 1:
            first_seen: dict[int, float] = {}
            for f in frames:
                first_seen.setdefault(f["dlc"], round(f["ts"] - start, 4))
            anomalies.append({
                "class": "dlc_change", "aid": aid,
                "detail": f"DLC changed between {dlcs} during the capture",
                "frames": [{"offset_s": round(f["ts"] - start, 4), "dlc": f["dlc"],
                            "data": _hex(f["data"])} for f in frames[:6]],
                "first_seen_offset_s": first_seen})
        # 3) period deviation (split-half mean inter-arrival)
        if len(frames) >= MIN_FRAMES_PERIOD_SPLIT:
            half = len(frames) // 2
            early = [b["ts"] - a2["ts"] for a2, b in zip(frames[:half], frames[1:half + 1])]
            late = [b["ts"] - a2["ts"] for a2, b in zip(frames[half:], frames[half + 1:])]
            if early and late:
                e_mean = statistics.fmean(early) * 1000
                l_mean = statistics.fmean(late) * 1000
                ratio = abs(l_mean - e_mean) / e_mean if e_mean else 0.0
                if ratio > PERIOD_DEVIATION_RATIO:
                    anomalies.append({
                        "class": "period_deviation", "aid": aid,
                        "detail": (f"mean inter-arrival moved {e_mean:.2f} ms -> {l_mean:.2f} ms "
                                   f"({ratio * 100:.1f}% change, threshold "
                                   f"{int(PERIOD_DEVIATION_RATIO * 100)}%)"),
                        "frames": [{"offset_s": round(f["ts"] - start, 4),
                                    "data": _hex(f["data"])} for f in frames[-5:]]})
        # 4) counter discontinuity
        counter = a.get("counter")
        if counter:
            idx = counter["byte"]
            events = []
            for prev, cur in zip(frames, frames[1:]):
                if len(prev["data"]) <= idx or len(cur["data"]) <= idx:
                    continue
                delta = (cur["data"][idx] - prev["data"][idx]) & 0xFF
                if delta > COUNTER_SKIP_MIN:
                    events.append({"offset_s": round(cur["ts"] - start, 4),
                                   "from": f"0x{prev['data'][idx]:02X}",
                                   "to": f"0x{cur['data'][idx]:02X}", "delta": delta})
            if events:
                anomalies.append({
                    "class": "counter_discontinuity", "aid": aid,
                    "detail": (f"counter byte {idx} jumped by "
                               f"{', '.join(str(e['delta']) for e in events[:4])} "
                               f"(expected +1 per frame)"),
                    "frames": events[:6]})
        # 5) payload frozen
        if len({f["data"] for f in frames}) >= 3:
            run = 1
            longest = 1
            longest_at = 0
            for i, (prev, cur) in enumerate(zip(frames, frames[1:]), start=1):
                if cur["data"] == prev["data"]:
                    run += 1
                    if run > longest:
                        longest, longest_at = run, i - run + 1
                else:
                    run = 1
            if longest >= FROZEN_RUN:
                frozen = frames[longest_at:longest_at + longest]
                anomalies.append({
                    "class": "payload_frozen", "aid": aid,
                    "detail": (f"payload frozen for {longest} consecutive frames "
                               f"({(frozen[-1]['ts'] - frozen[0]['ts']) * 1000:.1f} ms) after "
                               f"earlier variation"),
                    "frames": [{"offset_s": round(f["ts"] - start, 4),
                                "data": _hex(f["data"])} for f in frozen[:5]]})
    return anomalies


# ================================================================== helpers ==
def still_sev_hi(fully_static: list[dict], proven: dict) -> bool:
    """Medium only when a fully static ID was demonstrably re-injected and received."""
    return bool(fully_static) and int(proven.get("observed") or 0) > 0


def target_channel(targets: list[str]) -> str | None:
    for raw in targets or []:
        t = str(raw).strip()
        for prefix in ("socketcan://", "socketcan:", "can://", "can:", "vcan://", "vcan:"):
            if t.startswith(prefix):
                return t[len(prefix):].strip("/") or None
        if re.match(r"^(can|vcan|slcan|pcan|kvaser|ixxat|vector)\d+$", t):
            return t
    return None


def parse_ip_link(text: str) -> list[dict]:
    rows: list[dict] = []
    cur: dict | None = None
    for line in (text or "").splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)(?:@[^:]+)?:\s+<([^>]*)>(.*)$", line)
        if m:
            cur = {"name": m.group(1), "flags": m.group(2), "excerpt": m.group(3).strip()}
            rows.append(cur)
            continue
        if cur is not None and line[:1].isspace():
            cur["excerpt"] += " " + line.strip()
    for row in rows:
        blob = row["excerpt"].lower()
        row["can"] = bool(re.search(r"link/can|can (state|bitrate|restart-ms|ctrlmode|bittiming)", blob)
                          or "can <" in blob)
        row["excerpt"] = row["excerpt"][:220]
    return rows


def socketcan_interfaces() -> list[dict]:
    res = runner.run(["ip", "-details", "link", "show"], timeout=10)
    return [r for r in parse_ip_link(res.stdout) if r["can"]]


def _capture_live(bus, seconds: float) -> tuple[list[dict], float, float]:
    frames: list[dict] = []
    start = time.time()
    end = start + seconds
    while time.time() < end and len(frames) < MAX_FRAMES:
        msg = bus.recv(timeout=0.05)
        if msg is None:
            continue
        data = bytes(msg.data or b"")
        frames.append({"ts": float(msg.timestamp or time.time()), "aid": int(msg.arbitration_id),
                       "ext": bool(msg.is_extended_id),
                       "dlc": int(msg.dlc if msg.dlc is not None else len(data)),
                       "data": data, "remote": bool(msg.is_remote_frame),
                       "error": bool(msg.is_error_frame)})
    return frames, start, time.time()


def seed_requested(entry: dict) -> str | None:
    resp = entry.get("response")
    if not resp:
        return None
    raw = bytes.fromhex(resp.replace(" ", ""))
    if raw[0] != 0x67 or len(raw) < 6:
        return None
    return raw[2:6].hex().upper()


def decode_ascii(hex_response: str | None, skip: int = 0) -> str:
    if not hex_response:
        return ""
    raw = bytes.fromhex(hex_response.replace(" ", ""))[skip:]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)


def format_uds_log(entries: list[dict]) -> str:
    lines = []
    for e in entries:
        lines.append(f"[{e.get('label', e.get('request', ''))}]")
        lines.append(f"  request : {e.get('request')}")
        lines.append(f"  tx frames (server): {e.get('raw_frames')}")
        lines.append(f"  response: {e.get('response')}  nrc={e.get('nrc')} "
                     f"positive={e.get('positive')}"
                     + (f"  ascii={e['payload_ascii']}" if e.get("payload_ascii") else ""))
    return "\n".join(lines) + "\n"
