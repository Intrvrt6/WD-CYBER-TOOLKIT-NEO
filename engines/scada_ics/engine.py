"""Module C - SCADA / ICS Pentest.

Real observations only:

  * TCP reachability of the declared ICS port (and a bounded nmap port probe).
  * Modbus/TCP transactions on the wire (function 0x01/0x02/0x03/0x04 and the
    0x2B/0x0E Read Device Identification MEI request) with the exact frames.
  * OPC UA GetEndpoints() over the wire (asyncua), plus a depth-limited browse
    of the address space to count nodes and find visible writable variables.
  * DNP3 link-status frame (start bytes 0x05 0x64) and EtherNet/IP ListIdentity
    (command 0x0063) probes for non-Modbus plants.
  * Local routing/interface state for the segmentation review.

Lab mode (`ctx.mode == "lab"`) starts an in-process pymodbus TCP server and an
in-process asyncua server on this host and runs the *same* checks against them,
so every result is reproducible without plant access. Nothing is fabricated: a
missing dependency or unreachable endpoint yields `base.unavailable(...)`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import threading
import time
from typing import Any

from backend import runner
from engines.base import Context, Result, have, unavailable

# --------------------------------------------------------------- dependencies
try:  # pymodbus >= 3.x
    from pymodbus import ModbusDeviceIdentification
    from pymodbus.server import ModbusTcpServer
    from pymodbus.simulator import DataType, SimData, SimDevice

    HAVE_PYMODBUS = True
    PYMODBUS_ERROR = ""
except Exception as _exc:  # pragma: no cover - depends on host packages
    HAVE_PYMODBUS = False
    PYMODBUS_ERROR = f"{type(_exc).__name__}: {_exc}"

try:  # asyncua (needs `crypto` for its import path)
    from asyncua import Client as UaClient
    from asyncua import Server as UaServer
    from asyncua import ua as ua

    HAVE_ASYNCUA = True
    ASYNCUA_ERROR = ""
except Exception as _exc:  # pragma: no cover - depends on host packages
    HAVE_ASYNCUA = False
    ASYNCUA_ERROR = f"{type(_exc).__name__}: {_exc}"


# ------------------------------------------------------------------- constants
DEFAULT_PORTS = {"modbus": 502, "opcua": 4840, "dnp3": 20000, "enip": 44818}
SCHEMES = {
    "modbus": "modbus", "modbustcp": "modbus", "modbus-tcp": "modbus", "mbap": "modbus",
    "tcp": "modbus", "opcua": "opcua", "opc-ua": "opcua", "opc.tcp": "opcua",
    "opcuatcp": "opcua", "dnp3": "dnp3", "enip": "enip", "ethernetip": "enip",
    "ethernet-ip": "enip", "enip-udp": "enip", "cip": "enip",
}

MODBUS_FUNCTION_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
}
READ_ONLY_OPS = {
    "modbus:0x01", "modbus:0x02", "modbus:0x03", "modbus:0x04", "modbus:0x2B/0x0E",
    "opcua:GetEndpoints", "opcua:Browse", "opcua:Read", "dnp3:link_status",
    "enip:list_identity", "local:ip_route", "local:ip_addr", "local:nmap_port_probe",
}

# Well-known ICS weaknesses used for correlation. Only ever emitted when an
# observation supports the entry; the observed fact is cited in the Result.
ICS_WEAKNESSES: dict[str, dict[str, Any]] = {
    "modbus_no_auth": {
        "title": "Modbus/TCP has no authentication or session concept",
        "cwe": ["CWE-306", "CWE-319"], "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "remediation": ("Treat the Modbus conduit as implicitly trusted: put it behind a firewall with "
                        "protocol-aware rules, front legacy PLCs with a Modbus/TCP security gateway, and "
                        "alert on unexpected unit IDs, function codes and write operations."),
    },
    "modbus_cleartext": {
        "title": "Modbus/TCP payloads are cleartext and carry no integrity check",
        "cwe": ["CWE-319", "CWE-345"], "cvss": 6.5,
        "vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "remediation": ("Confine Modbus to a control-system VLAN, use 802.1X/port security on that segment, "
                        "and add an IDS with Modbus/TCP rules to detect forged responses."),
    },
    "opcua_none_policy": {
        "title": "OPC UA endpoint advertises SecurityPolicy None",
        "cwe": ["CWE-319", "CWE-306"], "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "remediation": ("Publish a Basic256Sha256 (Sign & Encrypt) endpoint, remove the None endpoint or "
                        "keep it only for discovery, and trust-list client application certificates."),
    },
    "opcua_anonymous": {
        "title": "OPC UA server accepts an anonymous user identity",
        "cwe": ["CWE-306"], "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "remediation": ("Disable the Anonymous token policy on production endpoints and require "
                        "username/certificate identity mapped to an IEC 62443 role."),
    },
    "opcua_writable_visible": {
        "title": "Writable OPC UA variables are visible to an unauthenticated client",
        "cwe": ["CWE-732", "CWE-306"], "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "remediation": ("Set a restrictive AccessLevel per node, expose only the tags a client needs, and "
                        "require an authenticated, encrypted session for write-capable roles."),
    },
    "dnp3_no_auth": {
        "title": "DNP3 has no authentication in its default (pre-secure-auth) profile",
        "cwe": ["CWE-306", "CWE-345"], "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "remediation": "Enable DNP3 Secure Authentication v5 with pre-shared or certificated keys on the outstation.",
    },
    "enip_listidentity": {
        "title": "EtherNet/IP answers ListIdentity to any unauthenticated sender",
        "cwe": ["CWE-200", "CWE-306"], "cvss": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": ("Filter UDP/44818 at the cell boundary and disable unused discovery services on "
                        "controllers that do not need them."),
    },
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ================================================================== lab models
def _quiet_library_logs() -> None:
    """The simulators log every frame and a benign device-0 KeyError at INFO/WARN.

    Silencing them keeps engine output readable; nothing about the observation
    changes because every frame this engine uses is captured on its own socket.
    """
    for name in ("pymodbus", "pymodbus.server", "pymodbus.logging", "asyncua",
                 "asyncua.server", "asyncua.client"):
        logging.getLogger(name).setLevel(logging.CRITICAL)


class LabHandle:
    """Handle for an in-process simulator started by this engine."""

    def __init__(self, protocol: str, port: int) -> None:
        self.protocol = protocol
        self.port = port
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.server: Any = None
        self.done: threading.Event | None = None
        self._stop = False
        self._stopped = False
        self.started_at = time.time()
        self.stopped_at: float | None = None
        self.stop_elapsed_s: float | None = None

    # -- lifecycle ---------------------------------------------------------
    def stop(self) -> None:
        self._stop = True
        if self.protocol == "modbus" and self.server is not None and self.loop is not None:
            try:
                asyncio.run_coroutine_threadsafe(self.server.shutdown(), self.loop).result(10)
            except Exception:
                pass
        if self.protocol == "opcua" and self.done is not None:
            # Let the serving coroutine leave `async with server` (which stops the
            # asyncua server) inside the still-running loop, then stop the loop.
            self.done.wait(15)
        if self.loop is not None:
            try:
                if self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception:
                pass
        if self.thread is not None:
            self.thread.join(10)
        if self.loop is not None:
            try:
                if not self.loop.is_running():
                    self.loop.close()
            except Exception:
                pass

    def as_dict(self) -> dict:
        return {"protocol": self.protocol, "port": self.port,
                "uptime_s": round(time.time() - self.started_at, 2)}


class LabModbusHandle(LabHandle):
    def __init__(self, port: int, unit: int, units: list[int]) -> None:
        super().__init__("modbus", port)
        self.unit = unit
        self.units = units
        self.identity: dict[str, str] = {}


class LabOpcUaHandle(LabHandle):
    def __init__(self, port: int) -> None:
        super().__init__("opcua", port)
        self.url = f"opc.tcp://127.0.0.1:{port}/neo/lab"
        self.writable_nodes: list[str] = []


def _wait_for_port(host: str, port: int, timeout: float = 12.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def start_lab_modbus(port: int = 5020, unit: int = 1) -> LabModbusHandle:
    """Start a real pymodbus TCP server in a daemon thread.

    Deterministic data model: coils all TRUE, discrete inputs all FALSE, holding
    registers 20..27, input registers 100..107, and a device identification
    block. A second unit id (unit + 1) is served so the unit-id sweep has a
    second real answer.
    """
    if not HAVE_PYMODBUS:
        raise RuntimeError(f"pymodbus is unavailable: {PYMODBUS_ERROR}")

    _quiet_library_logs()
    handle = LabModbusHandle(port, unit, [unit, unit + 1])
    identity = {
        "VendorName": "Neo Lab Instruments",
        "ProductCode": "NLB-MB01",
        "VendorUrl": "https://neolab.invalid/modbus",
        "ProductName": "NeoLab RTU Simulator",
        "ModelName": "NLB-1600",
        "MajorMinorRevision": "1.4.2",
    }
    handle.identity = dict(identity)

    def build_device(dev_id: int, hr_base: int) -> "SimDevice":
        coils = [SimData(0, count=16, values=True, datatype=DataType.BITS)]
        inputs = [SimData(0, count=16, values=False, datatype=DataType.BITS)]
        holding = [SimData(0, count=8, values=[hr_base + i for i in range(8)],
                          datatype=DataType.REGISTERS)]
        input_regs = [SimData(0, count=8, values=[100 + i for i in range(8)],
                              datatype=DataType.REGISTERS)]
        return SimDevice(dev_id, simdata=(coils, inputs, holding, input_regs))

    devices = [build_device(unit, 20), build_device(unit + 1, 40)]
    idn = ModbusDeviceIdentification(info_name=identity)

    handle.loop = asyncio.new_event_loop()

    async def _serve() -> None:
        handle.server = ModbusTcpServer(devices, address=("127.0.0.1", port), identity=idn)
        await handle.server.serve_forever()

    def _run() -> None:
        asyncio.set_event_loop(handle.loop)
        try:
            handle.loop.run_until_complete(_serve())
        except Exception:  # pragma: no cover - shutdown races
            pass

    handle.thread = threading.Thread(target=_run, name=f"lab-modbus-{port}", daemon=True)
    handle.thread.start()
    if not _wait_for_port("127.0.0.1", port):
        handle.stop()
        raise RuntimeError(f"lab Modbus server did not start listening on 127.0.0.1:{port}")
    return handle


def start_lab_opcua(port: int = 4840) -> LabOpcUaHandle:
    """Start a real asyncua server (own thread + event loop), SecurityPolicy None.

    Small address space: Objects/Process with ReactorTemperature (writable),
    LinePressure, ValveOpen and a Maintenance/SetpointScale writable variable,
    so a depth-limited browse finds real writable nodes.
    """
    if not HAVE_ASYNCUA:
        raise RuntimeError(f"asyncua is unavailable: {ASYNCUA_ERROR}")

    _quiet_library_logs()
    handle = LabOpcUaHandle(port)
    handle.loop = asyncio.new_event_loop()
    handle.done = threading.Event()
    ready = threading.Event()

    async def _serve() -> None:
        server = UaServer()
        try:
            await server.init()
            server.set_endpoint(handle.url)
            server.set_server_name("NeoLab OPC UA Simulator")
            idx = await server.register_namespace("http://neolab.invalid/ua")
            process = await server.nodes.objects.add_folder(idx, "Process")
            temp = await process.add_variable(idx, "ReactorTemperature", 21.5)
            await temp.set_writable()
            handle.writable_nodes.append("Process/ReactorTemperature")
            await process.add_variable(idx, "LinePressure", 3.2)
            await process.add_variable(idx, "ValveOpen", True)
            maintenance = await server.nodes.objects.add_folder(idx, "Maintenance")
            scale = await maintenance.add_variable(idx, "SetpointScale", 1.0)
            await scale.set_writable()
            handle.writable_nodes.append("Maintenance/SetpointScale")
            handle.server = server
            async with server:
                ready.set()
                while not handle._stop:
                    await asyncio.sleep(0.15)
        finally:
            # The `async with` above already stopped the server; signal the
            # stopping thread so it does not close the loop underneath us.
            handle.done.set()

    def _run() -> None:
        asyncio.set_event_loop(handle.loop)
        try:
            handle.loop.run_until_complete(_serve())
        except Exception:  # pragma: no cover - shutdown races
            pass
        finally:
            handle.done.set()

    handle.thread = threading.Thread(target=_run, name=f"lab-opcua-{port}", daemon=True)
    handle.thread.start()
    if not ready.wait(25):
        handle.stop()
        raise RuntimeError(f"lab OPC UA server did not initialise on 127.0.0.1:{port}")
    if not _wait_for_port("127.0.0.1", port):
        handle.stop()
        raise RuntimeError(f"lab OPC UA server did not listen on 127.0.0.1:{port}")
    return handle


# ============================================================= wire primitives
def tcp_probe(host: str, port: int, timeout: float = 2.5) -> dict:
    """Plain TCP connect probe; records timing and any unsolicited banner bytes."""
    started = time.time()
    out: dict[str, Any] = {"host": host, "port": port, "connected": False, "protocol": "tcp"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            out["connected"] = True
            out["connect_ms"] = round((time.time() - started) * 1000, 2)
            sock.settimeout(min(0.8, timeout))
            try:
                banner = sock.recv(64)
                if banner:
                    out["banner_hex"] = banner.hex()
                    out["banner_ascii"] = _printable(banner)
            except socket.timeout:
                out["banner_hex"] = ""
            except OSError:
                out["banner_hex"] = ""
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["connect_ms"] = round((time.time() - started) * 1000, 2)
    return out


def _printable(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def mbap_frame(unit: int, pdu: bytes, tid: int = 1) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def modbus_exchange(host: str, port: int, unit: int, pdu: bytes, tid: int = 1,
                    timeout: float = 2.5) -> dict:
    """Send one Modbus/TCP PDU and capture the exact request/response bytes."""
    frame = mbap_frame(unit, pdu, tid)
    started = time.time()
    out: dict[str, Any] = {
        "transport": "modbus/tcp", "host": host, "port": port, "unit": unit,
        "request_hex": frame.hex(), "response_hex": "",
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(frame)
            header = _recv_exact(sock, 6)
            if len(header) < 6:
                out["error"] = f"short MBAP header ({len(header)} bytes)"
                return out
            length = struct.unpack(">H", header[4:6])[0]
            # MBAP `length` counts the unit id plus the whole PDU, so the bytes
            # after the 6-byte header are exactly `length` (this includes the
            # unit id that was already consumed as header[6:7] of the request).
            body = _recv_exact(sock, max(0, length))
            response = header + body
            out["response_hex"] = response.hex()
            out["response_bytes"] = len(response)
            out["mbap_length"] = length
            out["truncated"] = len(body) < length
            # body[0] is the unit id; the PDU begins at body[1].
            pdu_bytes = body[1:]
            if len(pdu_bytes) >= 1:
                out["function_code"] = f"0x{pdu_bytes[0]:02X}"
                if pdu_bytes[0] & 0x80 and len(pdu_bytes) >= 2:
                    out["exception_code"] = f"0x{pdu_bytes[1]:02X}"
                    out["exception_name"] = MODBUS_EXCEPTIONS.get(pdu_bytes[1], "unknown")
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    out["duration_ms"] = round((time.time() - started) * 1000, 1)
    return out


MODBUS_EXCEPTIONS = {
    0x01: "Illegal Function", 0x02: "Illegal Data Address", 0x03: "Illegal Data Value",
    0x04: "Server Device Failure", 0x05: "Acknowledge", 0x06: "Server Device Busy",
    0x08: "Memory Parity Error", 0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed To Respond",
}


def modbus_payload(response_hex: str) -> bytes:
    """Return the PDU bytes (function code onward) of a captured Modbus response."""
    try:
        raw = bytes.fromhex(response_hex)
    except ValueError:
        return b""
    if len(raw) < 9:
        return b""
    return raw[7:]


def parse_registers(response_hex: str) -> list[int]:
    pdu = modbus_payload(response_hex)
    if not pdu or pdu[0] & 0x80 or len(pdu) < 2:
        return []
    byte_count = pdu[1]
    data = pdu[2:2 + byte_count]
    return [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, len(data) - 1, 2)]


def parse_bits(response_hex: str, count: int) -> list[bool]:
    pdu = modbus_payload(response_hex)
    if not pdu or pdu[0] & 0x80 or len(pdu) < 2:
        return []
    byte_count = pdu[1]
    data = pdu[2:2 + byte_count]
    bits: list[bool] = []
    for byte in data:
        for bit in range(8):
            bits.append(bool(byte & (1 << bit)))
    return bits[:count]


MEI_OBJECT_NAMES = {
    0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision",
    0x03: "VendorUrl", 0x04: "ProductName", 0x05: "ModelName",
    0x06: "UserApplicationName",
}


def parse_mei(response_hex: str) -> dict:
    """Decode a Read Device Identification (0x2B/0x0E) response."""
    pdu = modbus_payload(response_hex)
    out: dict[str, Any] = {}
    if len(pdu) < 7 or pdu[0] != 0x2B:
        return out
    if pdu[0] & 0x80:
        return {"exception": pdu[1] if len(pdu) > 1 else None}
    out["mei_type"] = f"0x{pdu[1]:02X}"
    out["read_code"] = f"0x{pdu[2]:02X}"
    out["conformity_level"] = f"0x{pdu[3]:02X}"
    out["more_follows"] = pdu[4]
    out["next_object_id"] = pdu[5]
    count = pdu[6]
    objects: dict[str, str] = {}
    i = 7
    for _ in range(count):
        if i + 1 >= len(pdu):
            break
        obj_id = pdu[i]
        length = pdu[i + 1]
        value = pdu[i + 2:i + 2 + length]
        objects[MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")] = value.decode(
            "utf-8", errors="replace")
        i += 2 + length
    out["objects"] = objects
    return out


def dnp3_crc(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def dnp3_link_status_frame(dest: int = 1, src: int = 3) -> bytes:
    body = bytes([0x05, 0x64, 0x05, 0xC9]) + struct.pack("<HH", dest, src)
    return body + struct.pack("<H", dnp3_crc(body))


def probe_dnp3(host: str, port: int, timeout: float = 2.5) -> dict:
    frame = dnp3_link_status_frame()
    out: dict[str, Any] = {"transport": "dnp3/tcp", "host": host, "port": port,
                           "request_hex": frame.hex(), "response_hex": "",
                           "start_bytes": "0564", "confirmed": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(frame)
            response = sock.recv(292)
            out["response_hex"] = response.hex()
            out["confirmed"] = response[:2] == b"\x05\x64"
            out["start_bytes_observed"] = response[:2].hex() if response else ""
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def probe_enip_list_identity(host: str, port: int = 44818, timeout: float = 2.5) -> dict:
    """EtherNet/IP ListIdentity (encapsulation command 0x0063) over UDP."""
    request = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
    out: dict[str, Any] = {"transport": "ethernet-ip/udp", "host": host, "port": port,
                           "request_hex": request.hex(), "response_hex": "",
                           "confirmed": False}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(request, (host, port))
            response, peer = sock.recvfrom(2048)
            out["response_hex"] = response.hex()
            out["response_bytes"] = len(response)
            if len(response) >= 24:
                command, _length = struct.unpack("<HH", response[:4])
                out["command"] = f"0x{command:04X}"
                out["confirmed"] = command == 0x0063
                identity = parse_enip_identity(response)
                if identity:
                    out["identity"] = identity
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def parse_enip_identity(response: bytes) -> dict:
    """Parse the ListIdentity CPF payload; returns {} if the shape is unexpected."""
    try:
        if len(response) < 30:
            return {}
        item_count = struct.unpack("<H", response[24:26])[0]
        if item_count < 1:
            return {}
        item_type, item_len = struct.unpack("<HH", response[26:30])
        body = response[30:30 + item_len]
        if item_type != 0x000C or len(body) < 34:
            return {}
        pos = 18  # skip encap version (2) + socket address (16)
        vendor_id, device_type, product_code, revision, status = struct.unpack(
            "<HHHHH", body[pos:pos + 10])
        pos += 10
        serial = struct.unpack("<I", body[pos:pos + 4])[0]
        pos += 4
        name_len = body[pos]
        name = body[pos + 1:pos + 1 + name_len].decode("utf-8", errors="replace")
        return {"vendor_id": vendor_id, "device_type": device_type,
                "product_code": product_code, "revision": revision,
                "status": status, "serial": serial, "product_name": name}
    except (struct.error, IndexError):
        return {}


async def _ua_observe(url: str, depth: int, node_cap: int, timeout: float) -> dict:
    out: dict[str, Any] = {"url": url, "connected": False, "endpoints": [],
                           "node_count": 0, "writable_nodes": [], "variables_sample": [],
                           "depth": depth, "node_cap": node_cap}
    client = UaClient(url, timeout=timeout)
    try:
        await asyncio.wait_for(client.connect(), timeout=timeout)
        out["connected"] = True
        out["identity"] = "anonymous"  # no user/credential was set on the client
        endpoints = await asyncio.wait_for(client.get_endpoints(), timeout=timeout)
        for ep in endpoints:
            app = ep.Server
            entry = {
                "endpoint_url": ep.EndpointUrl,
                "security_policy": str(ep.SecurityPolicyUri),
                "security_mode": int(ep.SecurityMode),
                "security_level": getattr(ep, "SecurityLevel", None),
                "user_tokens": [str(t.TokenType) for t in (ep.UserIdentityTokens or [])],
                "anonymous_offered": any("Anonymous" in str(t.TokenType)
                                         for t in (ep.UserIdentityTokens or [])),
                "application_name": (app.ApplicationName.Text if app and app.ApplicationName else ""),
                "application_uri": (app.ApplicationUri if app else ""),
                "product_uri": (app.ProductUri if app else ""),
                "application_type": (int(app.ApplicationType) if app else None),
                "discovery_urls": list(app.DiscoveryUrls or []) if app else [],
                "has_server_certificate": bool(ep.ServerCertificate),
            }
            out["endpoints"].append(entry)
        out["build_info"] = await _ua_build_info(client, timeout)
        walk = await _ua_walk(client, depth, node_cap, timeout)
        out.update(walk)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), timeout=5)
        except Exception:
            pass
    return out


async def _ua_build_info(client: "UaClient", timeout: float) -> dict:
    """Read Server_ServerStatus_BuildInfo (i=2260) children."""
    info: dict[str, str] = {}
    try:
        node = client.get_node(ua.NodeId(2260))
        for child in await asyncio.wait_for(node.get_children(), timeout=timeout):
            try:
                name = (await child.read_browse_name()).Name
                value = await child.read_value()
                info[name] = str(value)
            except Exception:
                continue
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
    return info


async def _ua_walk(client: "UaClient", depth: int, node_cap: int,
                   timeout: float) -> dict:
    """Depth-limited breadth-first browse from the Objects folder."""
    out: dict[str, Any] = {"node_count": 0, "writable_nodes": [], "variables_sample": [],
                           "node_cap_hit": False, "browse_errors": 0}
    queue: list[tuple[Any, int, str]] = [(client.nodes.objects, 1, "")]
    visited = 0
    while queue:
        node, level, prefix = queue.pop(0)
        if level > depth:
            continue
        try:
            children = await asyncio.wait_for(node.get_children(), timeout=timeout)
        except Exception:
            out["browse_errors"] += 1
            continue
        for child in children:
            if visited >= node_cap:
                out["node_cap_hit"] = True
                queue.clear()
                break
            visited += 1
            try:
                node_class = (await child.read_attribute(
                    ua.AttributeIds.NodeClass)).Value.Value
            except Exception:
                node_class = None
            name = f"NodeId({child.nodeid})"
            try:
                name = (await child.read_browse_name()).Name
            except Exception:
                pass
            path = f"{prefix}/{name}" if prefix else name
            if node_class == ua.NodeClass.Variable:
                access = None
                try:
                    access = (await child.read_attribute(
                        ua.AttributeIds.UserAccessLevel)).Value.Value
                except Exception:
                    out["browse_errors"] += 1
                if access is not None and access & 0x02:
                    out["writable_nodes"].append(path)
                if len(out["variables_sample"]) < 40:
                    out["variables_sample"].append({"path": path, "user_access_level": access})
            elif node_class == ua.NodeClass.Object and level < depth:
                queue.append((child, level + 1, path))
    out["node_count"] = visited
    return out


def opcua_observe(url: str, depth: int = 3, node_cap: int = 1500,
                  timeout: float = 10.0) -> dict:
    """Run the async OPC UA observation from synchronous engine code."""
    logger = logging.getLogger("asyncua")
    previous = logger.level
    logger.setLevel(logging.ERROR)  # the stack warns loudly about policy None
    started = time.time()
    try:
        result = asyncio.run(_ua_observe(url, depth, node_cap, timeout))
    except RuntimeError as exc:  # e.g. already inside an event loop
        result = {"url": url, "connected": False,
                  "error": f"RuntimeError: {str(exc)[:200]}"}
    except Exception as exc:
        result = {"url": url, "connected": False,
                  "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    finally:
        logger.setLevel(previous)
    result["duration_ms"] = round((time.time() - started) * 1000, 1)
    return result


# ==================================================================== endpoints
def parse_endpoint(target: str, params: dict) -> dict | None:
    """Accept modbus://host:port, opc.tcp://host:port/path, host:port or host."""
    raw = (target or "").strip()
    if not raw:
        return None
    protocol = "unknown"
    rest = raw
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        protocol = SCHEMES.get(scheme.lower(), "unknown")
    path = ""
    if "/" in rest:
        rest, path = rest.split("/", 1)
        path = "/" + path
    host, port = rest, 0
    if ":" in rest and rest.count(":") == 1:
        host, port_text = rest.split(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            port = 0
    if protocol == "unknown":
        hint = str(params.get("protocol", "")).lower()
        protocol = SCHEMES.get(hint, "unknown")
    if not port:
        port = int(params.get("port") or DEFAULT_PORTS.get(protocol, 502))
    if not host:
        return None
    if protocol == "unknown":
        protocol = {502: "modbus", 4840: "opcua", 20000: "dnp3", 44818: "enip"}.get(port, "unknown")
    if protocol == "opcua":
        url = f"opc.tcp://{host}:{port}{path or '/neo/lab'}"
    else:
        url = f"{protocol}://{host}:{port}"
    return {"target": raw, "protocol": protocol, "host": host, "port": port,
            "path": path, "url": url, "key": f"{host}:{port}",
            "lab_simulated": False, "reused_listener": False}


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ===================================================================== state
class _State:
    """Per-run observations shared between the ten checks."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.source = "lab" if ctx.mode == "lab" else "live"
        self.eps: list[dict] = []
        self.primary: dict | None = None
        self.connect: dict[str, dict] = {}
        self.modbus: dict[str, dict] = {}
        self.opcua: dict[str, dict] = {}
        self.confirmed: dict[str, list[str]] = {}
        self.nmap: dict[str, Any] = {}
        self.route: dict[str, Any] = {}
        self.config: dict[str, Any] = {}
        self.correlations: list[dict] = []
        self.ops: list[dict] = []
        self.writes: dict[str, Any] = {}
        self.notes: list[str] = []
        self.handles: list[LabHandle] = []

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def record_op(self, transport: str, operation: str, detail: str,
                  access: str = "read") -> None:
        self.ops.append({"transport": transport, "operation": operation,
                         "detail": detail, "access": access})

    def by_protocol(self, protocol: str) -> list[dict]:
        return [e for e in self.eps if e["protocol"] == protocol]

    def worst(self) -> tuple[str, float]:
        severity, score = "info", 0.0
        for finding in self.ctx.findings:
            if finding.severity in SEVERITY_RANK and finding.severity != "info":
                if SEVERITY_RANK[finding.severity] < SEVERITY_RANK[severity]:
                    severity = finding.severity
                    score = finding.cvss_score or 0.0
        return severity, score


# ====================================================================== engine
class SCADAEngine:
    module = "scada_ics"
    title = "Module C - SCADA / ICS Pentest"
    description = ("Modbus/TCP and OPC UA service discovery, protocol identification, authentication and "
                   "configuration review, ICS weakness correlation and IEC 62443 zoning rationale - all "
                   "read-only, with exact protocol transcripts.")
    checks = [
        ("ICS-01", "ICS asset discovery (TCP reachability and port state)", True),
        ("ICS-02", "ICS protocol identification (Modbus / OPC UA / DNP3 / EtherNet-IP)", True),
        ("ICS-03", "ICS service inventory (unit IDs and server identification)", True),
        ("ICS-04", "Authentication assessment (no-auth by design vs policy)", True),
        ("ICS-05", "Segmentation review (routing and interface exposure)", True),
        ("ICS-06", "Configuration security review (read-only data and node exposure)", True),
        ("ICS-07", "Known ICS weakness correlation", True),
        ("ICS-08", "Risk classification and IEC 62443 zone/conduit rationale", True),
        ("ICS-09", "Evidence collection (raw protocol transcripts)", True),
        ("ICS-10", "Safe-stop and rollback verification (read-only attestation)", True),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        state = _State(ctx)
        self.st = state
        started: list[LabHandle] = []
        try:
            self._parse_targets(ctx)
            if not state.eps:
                ctx.add(unavailable("ICS-01", "ICS asset discovery",
                                    "No ICS endpoint could be parsed from the target list "
                                    "(expected modbus://host:port, opc.tcp://host:port or host:port)."))
                return ctx.findings
            if ctx.mode == "lab":
                started = self._prepare_lab(ctx)
            steps = [
                ("ICS-01", self.ics01_asset_discovery),
                ("ICS-02", self.ics02_protocol_identification),
                ("ICS-03", self.ics03_service_inventory),
                ("ICS-04", self.ics04_authentication),
                ("ICS-05", self.ics05_segmentation),
                ("ICS-06", self.ics06_configuration),
                ("ICS-07", self.ics07_correlate),
                ("ICS-08", self.ics08_risk),
                ("ICS-09", self.ics09_evidence),
                ("ICS-10", self.ics10_safe_stop),
            ]
            titles = {c[0]: c[1] for c in self.checks}
            for index, (check_id, fn) in enumerate(steps):
                if runner.executor.stopped():
                    ctx.add(Result(check_id, titles[check_id], "error", severity="info",
                                   description="Execution halted by emergency stop before this check ran.",
                                   source=state.source))
                    continue
                try:
                    fn(ctx)
                except Exception as exc:  # a failing check must not kill the run
                    ctx.add(Result(check_id, titles[check_id], "error", severity="info",
                                   description=f"Check raised an exception: {type(exc).__name__}: {exc}",
                                   asset=self._primary_asset(), source=state.source))
                ctx.progress(int((index + 1) / len(steps) * 100))
            return ctx.findings
        finally:
            for handle in started:
                try:
                    handle.stop()
                except Exception:
                    pass
            state.handles = []

    # -------------------------------------------------------------- targets --
    def _parse_targets(self, ctx: Context) -> None:
        state = self.st
        for target in ctx.targets:
            endpoint = parse_endpoint(target, ctx.params)
            if endpoint and all(endpoint["key"] != e["key"] for e in state.eps):
                state.eps.append(endpoint)
        if state.eps:
            state.primary = state.eps[0]

    def _primary_asset(self) -> str:
        if self.st.primary:
            return f"{self.st.primary['host']}:{self.st.primary['port']}"
        return ""

    # ------------------------------------------------------------- lab setup --
    def _prepare_lab(self, ctx: Context) -> list[LabHandle]:
        """Reuse an existing listener, otherwise start a simulator for it."""
        state = self.st
        started: list[LabHandle] = []

        for endpoint in state.eps:
            if _port_open(endpoint["host"], endpoint["port"]):
                endpoint["reused_listener"] = True
                state.note(f"Reused already-listening listener on {endpoint['key']} "
                           f"(no simulator started)")
                continue
            try:
                if endpoint["protocol"] == "modbus":
                    handle = start_lab_modbus(endpoint["port"],
                                              unit=int(ctx.params.get("unit_id", 1)))
                elif endpoint["protocol"] == "opcua":
                    handle = start_lab_opcua(endpoint["port"])
                else:
                    state.note(f"No simulator exists for protocol '{endpoint['protocol']}'; "
                               f"{endpoint['key']} is probed as-is")
                    continue
            except Exception as exc:
                state.note(f"Could not start a {endpoint['protocol']} simulator on "
                           f"{endpoint['key']}: {exc}")
                continue
            started.append(handle)
            endpoint["lab_simulated"] = True

        # Lab mode also stands up the other well-known protocol so both the
        # Modbus and the OPC UA branches of every check have real data.
        wanted = ctx.params.get("lab_protocols") or ["modbus", "opcua"]
        for protocol in wanted:
            if any(e["protocol"] == protocol for e in state.eps):
                continue
            default_port = int(ctx.params.get(f"lab_{protocol}_port")
                               or DEFAULT_PORTS.get(protocol, 0))
            if not default_port or any(e["port"] == default_port for e in state.eps):
                continue
            try:
                if _port_open("127.0.0.1", default_port):
                    handle = None
                elif protocol == "modbus":
                    handle = start_lab_modbus(default_port, unit=int(ctx.params.get("unit_id", 1)))
                elif protocol == "opcua":
                    handle = start_lab_opcua(default_port)
                else:
                    continue
            except Exception as exc:
                state.note(f"Could not start the secondary {protocol} simulator on port "
                           f"{default_port}: {exc}")
                continue
            if handle is not None:
                started.append(handle)
            endpoint = {"target": f"{protocol}://127.0.0.1:{default_port}", "protocol": protocol,
                        "host": "127.0.0.1", "port": default_port, "path": "",
                        "url": (f"opc.tcp://127.0.0.1:{default_port}/neo/lab" if protocol == "opcua"
                                else f"{protocol}://127.0.0.1:{default_port}"),
                        "key": f"127.0.0.1:{default_port}", "lab_simulated": handle is not None,
                        "reused_listener": handle is None}
            state.eps.append(endpoint)
            state.note(f"Added lab {protocol} simulator endpoint {endpoint['key']} so the "
                       f"{protocol} checks run against a real service")
        state.handles = started
        return started

    # ------------------------------------------------------------- ICS-01 ----
    def ics01_asset_discovery(self, ctx: Context) -> None:
        state = self.st
        evidence: list[dict] = []
        lines: list[str] = []
        answered = 0
        for endpoint in state.eps:
            probe = tcp_probe(endpoint["host"], endpoint["port"], timeout=2.0)
            probe["endpoint"] = endpoint["url"]
            probe["lab_simulated"] = endpoint.get("lab_simulated", False)
            state.connect[endpoint["key"]] = probe
            state.record_op("local", "tcp_connect",
                            f"TCP connect {endpoint['host']}:{endpoint['port']}")
            evidence.append({"type": "other",
                             "summary": f"TCP connect probe {endpoint['host']}:{endpoint['port']}",
                             "probe": probe})
            if probe.get("connected"):
                answered += 1
                lines.append(f"{endpoint['host']}:{endpoint['port']}/tcp open "
                             f"(connect {probe.get('connect_ms')} ms"
                             + (f", banner {probe['banner_hex']}" if probe.get("banner_hex") else "")
                             + ")")
            else:
                lines.append(f"{endpoint['host']}:{endpoint['port']}/tcp no answer "
                             f"({probe.get('error')})")

        if have("nmap"):
            hosts = sorted({e["host"] for e in state.eps})[:10]
            ports = sorted({e["port"] for e in state.eps})
            argv = ["nmap", "-Pn", "-p", ",".join(str(p) for p in ports), "-T4",
                    "--host-timeout", "15s", *hosts]
            if ctx.intensity == "deep":
                argv = ["nmap", "-Pn", "-sV", "--version-light", "-p",
                        ",".join(str(p) for p in ports), "-T4", "--host-timeout", "20s", *hosts]
            result = runner.run(argv, timeout=90)
            state.record_op("local", "nmap_port_probe", " ".join(argv))
            open_ports = []
            for line in (result.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 2 and "/tcp" in parts[0] and parts[1] == "open":
                    open_ports.append({"port": parts[0], "service_hint": parts[2] if len(parts) > 2 else ""})
            state.nmap = {"argv": argv, "returncode": result.returncode,
                          "open": open_ports, "stdout": (result.stdout or "")[-8000:]}
            evidence.append(result.as_evidence())
        else:
            state.nmap = {"argv": [], "open": [], "stdout": "", "note": "nmap not installed"}

        status = "info" if answered else "fail"
        description = ("; ".join(lines) if lines else "No endpoint was probed.") + \
                      f" nmap reported {len(state.nmap.get('open', []))} open TCP port(s)."
        if any(e.get("lab_simulated") for e in state.eps):
            description += " Lab simulators were started for: " + ", ".join(
                e["key"] for e in state.eps if e.get("lab_simulated")) + "."
        ctx.add(Result("ICS-01", "ICS asset discovery completed", status, severity="info",
                       description=description, asset=self._primary_asset(),
                       source=state.source, evidence=evidence,
                       data={"endpoints": state.eps, "answered": answered,
                             "probed": len(state.eps), "nmap": state.nmap,
                             "lab": [h.as_dict() for h in state.handles],
                             "notes": state.notes}))

    # ------------------------------------------------------------- ICS-02 ----
    def ics02_protocol_identification(self, ctx: Context) -> None:
        state = self.st
        evidence: list[dict] = []
        found: list[str] = []
        missing: list[str] = []
        transcripts: list[str] = []

        for endpoint in state.eps:
            key, protocol = endpoint["key"], endpoint["protocol"]
            state.confirmed.setdefault(key, [])
            if not state.connect.get(key, {}).get("connected"):
                missing.append(f"{key}: TCP port closed, no protocol frame could be exchanged")
                continue
            if protocol in ("modbus", "unknown"):
                # A real Read Holding Registers request: function 0x03, addr 0, qty 4.
                exchange = modbus_exchange(endpoint["host"], endpoint["port"],
                                           unit=int(ctx.params.get("unit_id", 1)),
                                           pdu=bytes([0x03, 0x00, 0x00, 0x00, 0x04]))
                state.modbus.setdefault(key, {})["fc03"] = exchange
                state.record_op("modbus", "0x03", f"read_holding_registers unit="
                                 f"{ctx.params.get('unit_id', 1)} addr=0 count=4")
                ok = bool(exchange.get("response_hex")) and not exchange.get("error")
                registers = parse_registers(exchange.get("response_hex", ""))
                entry = {"type": "protocol_frame", "summary": f"Modbus/TCP function 0x03 to {key}",
                         "request_hex": exchange.get("request_hex"),
                         "response_hex": exchange.get("response_hex"),
                         "decoded_registers": registers,
                         "exception": exchange.get("exception_name"),
                         "duration_ms": exchange.get("duration_ms"),
                         "error": exchange.get("error")}
                evidence.append(entry)
                transcripts.append(format_modbus_transcript(
                    "0x03 Read Holding Registers (addr 0, count 4)", exchange))
                if ok and (registers or exchange.get("exception_code")):
                    state.confirmed[key].append("modbus")
                    found.append(f"{key}: Modbus/TCP confirmed by a real 0x03 response "
                                 f"({exchange.get('response_hex')})")
                else:
                    missing.append(f"{key}: no Modbus/TCP response ({exchange.get('error') or 'empty'})")
            if protocol == "opcua":
                observed = opcua_observe(endpoint["url"],
                                         depth=int(ctx.params.get("opcua_depth", 2)),
                                         timeout=float(ctx.params.get("opcua_timeout", 10)))
                state.opcua[key] = observed
                state.record_op("opcua", "GetEndpoints", f"GetEndpoints({endpoint['url']})")
                evidence.append({"type": "protocol_frame",
                                 "summary": f"OPC UA GetEndpoints against {endpoint['url']}",
                                 "connected": observed.get("connected"),
                                 "endpoint_count": len(observed.get("endpoints") or []),
                                 "endpoints": observed.get("endpoints"),
                                 "error": observed.get("error")})
                transcripts.append(format_opcua_transcript(endpoint["url"], observed))
                if observed.get("connected") and observed.get("endpoints"):
                    state.confirmed[key].append("opcua")
                    policies = sorted({e.get("security_policy", "?") for e in observed["endpoints"]})
                    found.append(f"{key}: OPC UA confirmed via GetEndpoints "
                                 f"({len(observed['endpoints'])} endpoint(s), policy {', '.join(policies)})")
                else:
                    missing.append(f"{key}: OPC UA session failed ({observed.get('error')})")
            if protocol == "dnp3":
                probe = probe_dnp3(endpoint["host"], endpoint["port"])
                state.modbus.setdefault(key, {})["dnp3"] = probe
                state.record_op("dnp3", "link_status", f"Link Status to {key}")
                evidence.append({"type": "protocol_frame", "summary": f"DNP3 link status to {key}",
                                 "request_hex": probe.get("request_hex"),
                                 "response_hex": probe.get("response_hex"),
                                 "start_bytes_observed": probe.get("start_bytes_observed"),
                                 "error": probe.get("error")})
                if probe.get("confirmed"):
                    state.confirmed[key].append("dnp3")
                    found.append(f"{key}: DNP3 confirmed (response start bytes 0x0564)")
                else:
                    missing.append(f"{key}: no DNP3 0x0564 response "
                                   f"({probe.get('error') or probe.get('response_hex') or 'silent'})")
            if protocol == "enip":
                probe = probe_enip_list_identity(endpoint["host"], endpoint["port"] or 44818)
                state.modbus.setdefault(key, {})["enip"] = probe
                state.record_op("enip", "list_identity", f"ListIdentity 0x0063 to {key}")
                evidence.append({"type": "protocol_frame", "summary": f"EtherNet/IP ListIdentity to {key}",
                                 "request_hex": probe.get("request_hex"),
                                 "response_hex": probe.get("response_hex"),
                                 "identity": probe.get("identity"),
                                 "error": probe.get("error")})
                if probe.get("confirmed"):
                    state.confirmed[key].append("enip")
                    found.append(f"{key}: EtherNet/IP confirmed (command 0x0063 answer)")
                else:
                    missing.append(f"{key}: no EtherNet/IP ListIdentity answer "
                                   f"({probe.get('error') or 'empty'})")

        if transcripts:
            state.config["protocol_transcripts"] = transcripts

        status = "pass" if found else "fail"
        description = ("; ".join(found) if found else "No ICS protocol could be confirmed on the target set.")
        if missing:
            description += " Not confirmed: " + "; ".join(missing) + "."
        ctx.add(Result("ICS-02", "ICS protocol identification", status, severity="info",
                       description=description, asset=self._primary_asset(),
                       source=state.source, evidence=evidence,
                       data={"confirmed": state.confirmed, "unconfirmed": missing}))

    # ------------------------------------------------------------- ICS-03 ----
    def ics03_service_inventory(self, ctx: Context) -> None:
        state = self.st
        evidence: list[dict] = []
        inventory: dict[str, Any] = {"endpoints": [], "unit_ids": {}, "servers": []}

        for endpoint in state.eps:
            key, protocol = endpoint["key"], endpoint["protocol"]
            record: dict[str, Any] = {"endpoint": endpoint["url"], "protocol": protocol,
                                      "port": endpoint["port"],
                                      "open": bool(state.connect.get(key, {}).get("connected")),
                                      "confirmed": state.confirmed.get(key, [])}
            if "modbus" in state.confirmed.get(key, []):
                units = sorted({int(ctx.params.get("unit_id", 1)), 1, 2, 247, 255})
                answers: list[dict] = []
                for unit in units[:5]:
                    exchange = modbus_exchange(endpoint["host"], endpoint["port"], unit,
                                               bytes([0x03, 0x00, 0x00, 0x00, 0x04]),
                                               timeout=1.5)
                    state.record_op("modbus", "0x03",
                                    f"read_holding_registers unit={unit} addr=0 count=4")
                    responded = bool(exchange.get("response_hex")) and not exchange.get("error")
                    answers.append({"unit_id": unit, "responded": responded,
                                    "response_hex": exchange.get("response_hex"),
                                    "exception": exchange.get("exception_name"),
                                    "registers": parse_registers(exchange.get("response_hex", ""))})
                record["unit_ids"] = answers
                inventory["unit_ids"][key] = answers
                devices: dict[str, Any] = {}
                for unit_entry in answers:
                    if not unit_entry["responded"] or unit_entry["exception"]:
                        continue
                    mei = modbus_exchange(endpoint["host"], endpoint["port"],
                                          unit_entry["unit_id"],
                                          bytes([0x2B, 0x0E, 0x02, 0x00]), timeout=1.5)
                    state.record_op("modbus", "0x2B/0x0E",
                                    f"read_device_identification unit={unit_entry['unit_id']}")
                    decoded = parse_mei(mei.get("response_hex", ""))
                    devices[str(unit_entry["unit_id"])] = {
                        "request_hex": mei.get("request_hex"),
                        "response_hex": mei.get("response_hex"),
                        "objects": decoded.get("objects", {}),
                        "conformity_level": decoded.get("conformity_level"),
                    }
                    evidence.append({"type": "protocol_frame",
                                     "summary": f"Modbus device identification unit "
                                                f"{unit_entry['unit_id']} on {key}",
                                     "request_hex": mei.get("request_hex"),
                                     "response_hex": mei.get("response_hex"),
                                     "objects": decoded.get("objects", {})})
                record["device_identification"] = devices
                if devices:
                    first = next(iter(devices.values()))["objects"]
                    clean_units = [a["unit_id"] for a in answers
                                   if a["responded"] and not a["exception"]]
                    inventory["servers"].append({
                        "protocol": "modbus", "endpoint": endpoint["url"],
                        "unit_ids_answering": [a["unit_id"] for a in answers if a["responded"]],
                        "unit_ids_serving_data": clean_units,
                        "unit_ids_exception_only": [a["unit_id"] for a in answers
                                                    if a["responded"] and a["exception"]],
                        "vendor": first.get("VendorName"), "product": first.get("ProductName"),
                        "model": first.get("ModelName"),
                        "revision": first.get("MajorMinorRevision")})
            if "opcua" in state.confirmed.get(key, []):
                observed = state.opcua.get(key) or opcua_observe(
                    endpoint["url"], depth=int(ctx.params.get("opcua_depth", 2)),
                    timeout=float(ctx.params.get("opcua_timeout", 10)))
                state.opcua[key] = observed
                for entry in observed.get("endpoints", []):
                    inventory["servers"].append({
                        "protocol": "opcua", "endpoint": entry.get("endpoint_url"),
                        "application_name": entry.get("application_name"),
                        "application_uri": entry.get("application_uri"),
                        "product_uri": entry.get("product_uri"),
                        "security_policy": entry.get("security_policy")})
                record["opcua_build_info"] = observed.get("build_info", {})
                record["opcua_application"] = [
                    {"application_name": e.get("application_name"),
                     "application_uri": e.get("application_uri"),
                     "product_uri": e.get("product_uri")}
                    for e in observed.get("endpoints", [])]
                evidence.append({"type": "other",
                                 "summary": f"OPC UA server identification for {endpoint['url']}",
                                 "build_info": observed.get("build_info", {}),
                                 "applications": record["opcua_application"]})
            inventory["endpoints"].append(record)

        summary = []
        for server in inventory["servers"]:
            if server["protocol"] == "modbus":
                summary.append(f"Modbus {server['endpoint']} units answering "
                               f"{server.get('unit_ids_answering')} "
                               f"(serving data: {server.get('unit_ids_serving_data')}, "
                               f"exception-only: {server.get('unit_ids_exception_only')}) "
                               f"vendor={server.get('vendor')!r} product={server.get('product')!r} "
                               f"model={server.get('model')!r} rev={server.get('revision')!r}")
            else:
                summary.append(f"OPC UA {server.get('endpoint')} app={server.get('application_name')!r} "
                               f"product_uri={server.get('product_uri')!r}")
        status = "info" if inventory["servers"] else "fail"
        description = ("; ".join(summary) if summary else
                       "No server identification was obtainable from the responding endpoints.")
        build = next((r.get("opcua_build_info") for r in inventory["endpoints"]
                      if r.get("opcua_build_info")), None)
        if build:
            description += (" OPC UA BuildInfo: "
                            + ", ".join(f"{k}={v}" for k, v in build.items() if k != "error")[:300] + ".")
        if not evidence:
            # Device identification (FC 0x2B/0x0E) and OPC UA endpoint browsing are the
            # *enrichment* of this check; when they time out on a slow lab server the
            # inventory still holds real observations, so attach those rather than
            # emitting a result with no evidence at all.
            unit_summary = {k: [u["unit_id"] for u in v if u.get("responded")]
                            for k, v in inventory["unit_ids"].items()}
            evidence = [{"type": "other",
                         "summary": "Service inventory from the endpoint/unit responses",
                         "method": "Modbus FC03 per unit (1, 2, 247, 255, params.unit_id) and "
                                   "OPC UA GetEndpoints when the protocol was confirmed",
                         "endpoints": inventory["endpoints"],
                         "unit_ids_responding": unit_summary,
                         "servers": inventory["servers"]}]
        ctx.add(Result("ICS-03", "ICS service inventory", status, severity="info",
                       description=description, asset=self._primary_asset(),
                       source=state.source, evidence=evidence, data=inventory))

    # ------------------------------------------------------------- ICS-04 ----
    def ics04_authentication(self, ctx: Context) -> None:
        state = self.st
        evidence: list[dict] = []
        facts: list[str] = []
        severity = "info"
        score, vector, cwes = None, None, []
        cvss = {"high": 7.5, "medium": 6.5, "low": 3.1}

        for endpoint in state.eps:
            key = endpoint["key"]
            if "modbus" in state.confirmed.get(key, []):
                exchange = (state.modbus.get(key) or {}).get("fc03") or {}
                read_ok = bool(exchange.get("response_hex")) and not exchange.get("error")
                if read_ok:
                    facts.append(f"{key}: Modbus/TCP answered unit {exchange.get('unit')} with no "
                                 f"credential of any kind (MBAP header has no identity field) - "
                                 f"register data returned: {parse_registers(exchange.get('response_hex', ''))}")
                    evidence.append({"type": "protocol_frame",
                                     "summary": f"Unauthenticated Modbus read accepted on {key}",
                                     "request_hex": exchange.get("request_hex"),
                                     "response_hex": exchange.get("response_hex")})
                    if SEVERITY_RANK.get(severity, 4) > SEVERITY_RANK["high"]:
                        severity, score, vector = "high", cvss["high"], \
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                        cwes = ["CWE-306", "CWE-319"]
            if "opcua" in state.confirmed.get(key, []):
                observed = state.opcua.get(key) or {}
                endpoints = observed.get("endpoints") or []
                policies = sorted({e.get("security_policy", "?") for e in endpoints})
                none_only = bool(policies) and all(p.endswith("#None") for p in policies)
                anonymous = bool(endpoints) and all(
                    any("Anonymous" in token for token in e.get("user_tokens", []))
                    for e in endpoints)
                anonymous_works = (observed.get("identity") == "anonymous"
                                   and bool(observed.get("connected")))
                anon_text = ("accepted (a session was established with no user token supplied)"
                             if anonymous_works else "not established")
                offered = sorted({t for e in endpoints for t in e.get("user_tokens", [])})
                facts.append(f"{key}: OPC UA SecurityPolicy observed = {', '.join(policies)}; "
                             f"anonymous identity {anon_text}; "
                             f"token policies offered = {offered}")
                evidence.append({"type": "other",
                                 "summary": f"OPC UA security policy and identity for {key}",
                                 "policies": policies, "anonymous_offered": anonymous,
                                 "connected_anonymously": observed.get("identity") == "anonymous"
                                 and bool(observed.get("connected")),
                                 "endpoints": [{"endpoint_url": e.get("endpoint_url"),
                                                "security_policy": e.get("security_policy"),
                                                "security_mode": e.get("security_mode"),
                                                "user_tokens": e.get("user_tokens")}
                                               for e in endpoints]})
                if none_only and anonymous:
                    facts.append(f"{key}: no encryption and no identity required - the endpoint is open "
                                 f"to any host that can reach the port")
                    if SEVERITY_RANK[severity] > SEVERITY_RANK["high"]:
                        severity, score, vector = "high", cvss["high"], \
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
                        cwes = ["CWE-306", "CWE-319"]
                elif none_only:
                    if SEVERITY_RANK[severity] > SEVERITY_RANK["medium"]:
                        severity, score, vector = "medium", cvss["medium"], \
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                        cwes = ["CWE-319"]
                elif anonymous and SEVERITY_RANK[severity] > SEVERITY_RANK["low"]:
                    severity, score, vector = "low", cvss["low"], \
                        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    cwes = ["CWE-306"]

        if not facts:
            ctx.add(unavailable("ICS-04", "Authentication assessment",
                                "No Modbus or OPC UA service answered, so authentication behaviour "
                                "could not be observed.", asset=self._primary_asset()))
            return
        status = "fail" if severity != "info" else "info"
        ctx.add(Result("ICS-04", "Authentication assessment", status, severity=severity,
                       description="; ".join(facts), asset=self._primary_asset(),
                       source=state.source,
                       cvss_score=score if status == "fail" else None,
                       cvss_vector=vector if status == "fail" else None,
                       cwe=cwes,
                       remediation=("Modbus/TCP: gateway the protocol or wrap it in a trusted conduit. "
                                    "OPC UA: publish a Basic256Sha256 Sign & Encrypt endpoint and disable "
                                    "the Anonymous token policy on production servers.")
                       if status == "fail" else "",
                       evidence=evidence, data={"facts": facts, "severity": severity}))

    # ------------------------------------------------------------- ICS-05 ----
    def ics05_segmentation(self, ctx: Context) -> None:
        state = self.st
        evidence: list[dict] = []
        addrs = runner.run(["ip", "-br", "addr"], timeout=10)
        state.record_op("local", "ip_addr", "ip -br addr")
        interfaces = []
        for line in (addrs.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                interfaces.append({"name": parts[0], "state": parts[1],
                                   "addresses": parts[2:]})
        evidence.append(addrs.as_evidence())

        paths: dict[str, Any] = {}
        for endpoint in state.eps:
            route = runner.run(["ip", "route", "get", endpoint["host"]], timeout=10)
            state.record_op("local", "ip_route", f"ip route get {endpoint['host']}")
            dev = ""
            for line in (route.stdout or "").splitlines():
                if " dev " in line:
                    dev = line.split(" dev ")[1].split()[0]
                    break
            default_iface = ""
            probe_route = runner.run(["ip", "route", "get", "198.51.100.1"], timeout=10)
            for line in (probe_route.stdout or "").splitlines():
                if " dev " in line:
                    default_iface = line.split(" dev ")[1].split()[0]
                    break
            general = bool(dev) and dev != "lo" and dev == default_iface
            paths[endpoint["key"]] = {
                "host": endpoint["host"], "port": endpoint["port"], "route_dev": dev,
                "default_interface": default_iface, "loopback": dev == "lo",
                "general_purpose_interface": general,
                "route_stdout": (route.stdout or "").strip()[:400]}
            evidence.append(route.as_evidence())

        exposed = [k for k, v in paths.items() if v["general_purpose_interface"]]
        lab_only = [k for k, v in paths.items() if v["loopback"]]
        if exposed:
            text = ("ICS service reachable over general-purpose interface(s): "
                    + "; ".join(f"{k} via {paths[k]['route_dev']}" for k in exposed)
                    + " - the control protocol shares an interface with ordinary host traffic.")
        elif lab_only:
            text = ("All ICS endpoints resolve over loopback ("
                    + ", ".join(lab_only) + "); no network boundary is crossed on this host, so the "
                    "conduit itself was not exercised over a production segment.")
        else:
            text = "ICS endpoints are reachable, but no general-purpose interface was identified."
        if len({v["route_dev"] for v in paths.values() if v["route_dev"]}) > 1:
            text += " Note: endpoints resolve over more than one interface (" + \
                    ", ".join(sorted({v["route_dev"] for v in paths.values() if v["route_dev"]})) + ")."

        ctx.add(Result("ICS-05", "Segmentation review", "info", severity="info",
                       description=text, asset=self._primary_asset(), source=state.source,
                       evidence=evidence,
                       data={"interfaces": interfaces, "paths": paths,
                             "general_purpose_reachable": exposed, "loopback_only": lab_only,
                             "addrs_stdout": (addrs.stdout or "")[:2000]}))
        state.route = {"interfaces": interfaces, "paths": paths,
                       "general_purpose_reachable": exposed, "loopback_only": lab_only}

    # ------------------------------------------------------------- ICS-06 ----
    def ics06_configuration(self, ctx: Context) -> None:
        state = self.st
        evidence: list[dict] = []
        facts: list[str] = []
        config: dict[str, Any] = {"modbus": {}, "opcua": {}}

        for endpoint in state.eps:
            key = endpoint["key"]
            if "modbus" in state.confirmed.get(key, []):
                unit = int(ctx.params.get("unit_id", 1))
                reads = [
                    ("0x03", "holding registers 0-3", bytes([0x03, 0x00, 0x00, 0x00, 0x04])),
                    ("0x01", "coils 0-7", bytes([0x01, 0x00, 0x00, 0x00, 0x08])),
                    ("0x02", "discrete inputs 0-7", bytes([0x02, 0x00, 0x00, 0x00, 0x08])),
                    ("0x04", "input registers 0-3", bytes([0x04, 0x00, 0x00, 0x00, 0x04])),
                    ("0x2B/0x0E", "device identification", bytes([0x2B, 0x0E, 0x02, 0x00])),
                ]
                per_key: dict[str, Any] = {}
                for function, label, pdu in reads:
                    exchange = modbus_exchange(endpoint["host"], endpoint["port"], unit, pdu,
                                               timeout=1.5)
                    state.record_op("modbus", function,
                                    f"{label} unit={unit}" if function != "0x2B/0x0E"
                                    else f"read_device_identification unit={unit}")
                    per_key[function] = exchange
                    decoded: Any
                    if function in ("0x03", "0x04"):
                        decoded = parse_registers(exchange.get("response_hex", ""))
                    elif function in ("0x01", "0x02"):
                        decoded = parse_bits(exchange.get("response_hex", ""), 8)
                    else:
                        decoded = parse_mei(exchange.get("response_hex", ""))
                    per_key[function]["decoded"] = decoded
                    evidence.append({"type": "protocol_frame",
                                     "summary": f"Modbus {function} ({label}) on {key}",
                                     "request_hex": exchange.get("request_hex"),
                                     "response_hex": exchange.get("response_hex"),
                                     "decoded": decoded,
                                     "exception": exchange.get("exception_name")})
                    if exchange.get("response_hex"):
                        facts.append(f"{key} {function} {label}: "
                                     f"{json.dumps(decoded)[:200]}")
                    else:
                        facts.append(f"{key} {function} {label}: no response "
                                     f"({exchange.get('error') or 'silent'})")
                config["modbus"][key] = per_key
                # Keep every configuration-review frame in the shared transcript store
                # so ICS-09 saves the exact bytes for these reads too.
                merged = state.modbus.setdefault(key, {})
                for function, label, _pdu in reads:
                    merged[f"{function} ({label})"] = per_key[function]
                objects = (per_key.get("0x2B/0x0E", {}).get("decoded") or {}).get("objects", {})
                if objects:
                    facts.append(f"{key}: device identification exposed {objects} - network-readable "
                                 f"firmware/model detail useful for targeting known IOCs")
                holding = per_key.get("0x03", {}).get("decoded") or []
                config.setdefault("holding_values", {})[key] = holding
            if "opcua" in state.confirmed.get(key, []):
                observed = state.opcua.get(key) or {}
                depth = int(ctx.params.get("opcua_depth", 2))
                config["opcua"][key] = {
                    "depth": depth, "node_count": observed.get("node_count"),
                    "writable_nodes": observed.get("writable_nodes"),
                    "variables_sample": observed.get("variables_sample"),
                    "node_cap_hit": observed.get("node_cap_hit"),
                    "build_info": observed.get("build_info"),
                }
                facts.append(f"{key}: OPC UA address space browsed to depth {depth}: "
                             f"{observed.get('node_count')} node(s) visible"
                             + (f", {len(observed.get('writable_nodes') or [])} writable variable(s) "
                                f"visible to this reader: "
                                f"{(observed.get('writable_nodes') or [])[:10]}"
                                if observed.get("writable_nodes") else ", no writable variable visible"))
                evidence.append({"type": "other",
                                 "summary": f"OPC UA address-space exposure for {key}",
                                 "node_count": observed.get("node_count"),
                                 "writable_nodes": observed.get("writable_nodes"),
                                 "variables_sample": observed.get("variables_sample")})

        if not facts:
            ctx.add(unavailable("ICS-06", "Configuration security review",
                                "No Modbus or OPC UA service answered, so no configuration data "
                                "could be read.", asset=self._primary_asset()))
            return
        config["read_only"] = True
        ctx.add(Result("ICS-06", "Configuration security review", "info", severity="info",
                       description="Read-only configuration exposure: " + " | ".join(facts),
                       asset=self._primary_asset(), source=state.source, evidence=evidence,
                       data=config))
        state.config.update(config)

    # ------------------------------------------------------------- ICS-07 ----
    def ics07_correlate(self, ctx: Context) -> None:
        state = self.st
        correlations: list[dict] = []
        modbus_facts = []
        for key, frames in state.modbus.items():
            if frames.get("fc03", {}).get("response_hex") and "modbus" in state.confirmed.get(key, []):
                modbus_facts.append(key)
        if modbus_facts:
            for name in ("modbus_no_auth", "modbus_cleartext"):
                entry = dict(ICS_WEAKNESSES[name])
                entry.update({"id": name, "fact": (
                    f"{modbus_facts[0]} answered a Modbus/TCP function 0x03 request with "
                    f"response {state.modbus[modbus_facts[0]]['fc03'].get('response_hex')} "
                    f"without any credential (observation: ICS-04/ICS-02).")})
                correlations.append(entry)
        for key, observed in state.opcua.items():
            endpoints = observed.get("endpoints") or []
            if not endpoints:
                continue
            policies = {e.get("security_policy", "") for e in endpoints}
            if policies and all(p.endswith("#None") for p in policies):
                entry = dict(ICS_WEAKNESSES["opcua_none_policy"])
                entry.update({"id": "opcua_none_policy", "fact": (
                    f"{key} GetEndpoints returned SecurityPolicyUri 'None' for all "
                    f"{len(endpoints)} endpoint(s) (observation: ICS-02/ICS-04).")})
                correlations.append(entry)
            if observed.get("identity") == "anonymous" and observed.get("connected"):
                entry = dict(ICS_WEAKNESSES["opcua_anonymous"])
                entry.update({"id": "opcua_anonymous", "fact": (
                    f"{key}: an anonymous session (no user token supplied) was established and "
                    f"GetEndpoints/browse succeeded (observation: ICS-02/ICS-04).")})
                correlations.append(entry)
            if observed.get("writable_nodes"):
                entry = dict(ICS_WEAKNESSES["opcua_writable_visible"])
                entry.update({"id": "opcua_writable_visible", "fact": (
                    f"{key}: {len(observed['writable_nodes'])} variable(s) reported UserAccessLevel "
                    f"CurrentWrite: {observed['writable_nodes'][:6]} (observation: ICS-06).")})
                correlations.append(entry)
        for key, frames in state.modbus.items():
            if (frames.get("dnp3") or {}).get("confirmed"):
                entry = dict(ICS_WEAKNESSES["dnp3_no_auth"])
                entry.update({"id": "dnp3_no_auth", "fact": (
                    f"{key} answered an unauthenticated DNP3 link-status frame "
                    f"({frames['dnp3'].get('response_hex')}) (observation: ICS-02).")})
                correlations.append(entry)
            if (frames.get("enip") or {}).get("confirmed"):
                entry = dict(ICS_WEAKNESSES["enip_listidentity"])
                entry.update({"id": "enip_listidentity", "fact": (
                    f"{key} returned a ListIdentity payload to an unauthenticated UDP request: "
                    f"{(frames['enip'].get('identity') or {})} (observation: ICS-02).")})
                correlations.append(entry)

        state.correlations = correlations
        if not correlations:
            ctx.add(Result("ICS-07", "Known ICS weakness correlation", "info", severity="info",
                           description="No observation matched the in-code ICS weakness table; nothing "
                                       "was correlated (no claim is made).",
                           asset=self._primary_asset(), source=state.source,
                           evidence=[{"type": "other", "summary": "correlation table",
                                      "entries": []}],
                           data={"correlations": []}))
            return
        worst = min(correlations, key=lambda c: SEVERITY_RANK[sev_name(c.get("cvss", 0.0))])
        severity = sev_name(worst.get("cvss", 0.0))
        description = ("Correlated, not exploit-tested: "
                       + "; ".join(f"{c['title']} [{c['id']}, CVSS {c['cvss']}] because {c['fact']}"
                                   for c in correlations))
        ctx.add(Result("ICS-07", "Known ICS weakness correlation", "fail", severity=severity,
                       description=description, asset=self._primary_asset(), source=state.source,
                       cvss_score=worst.get("cvss"), cvss_vector=worst.get("vector"),
                       cwe=sorted({cwe for c in correlations for cwe in c["cwe"]}),
                       remediation=" ".join(dict.fromkeys(c["remediation"] for c in correlations)),
                       evidence=[{"type": "other",
                                  "summary": "ICS weakness correlations (correlated, not exploit-tested)",
                                  "entries": [{k: c[k] for k in ("id", "title", "cwe", "cvss",
                                                                 "vector", "fact")}
                                              for c in correlations]}],
                       data={"correlations": correlations, "exploit_tested": False}))

    # ------------------------------------------------------------- ICS-08 ----
    def ics08_risk(self, ctx: Context) -> None:
        state = self.st
        severity, score = state.worst()
        counts: dict[str, int] = {}
        for finding in ctx.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        routes = state.route.get("paths", {})
        conduits = [f"{k} via {v['route_dev']}"
                    for k, v in routes.items() if v.get("route_dev")]
        segment = ("loopback only (no production conduit crossed)"
                   if state.route.get("loopback_only") else
                   ("general-purpose interface: " + ", ".join(
                       state.route.get("general_purpose_reachable") or conduits)) if conduits
                   else "unknown conduit")
        rationale = (
            f"IEC 62443 zone/conduit view: the assessed asset(s) sit in the control-system zone and "
            f"are reachable over {segment}. A conduit that carries an unauthenticated, unencrypted "
            f"protocol does not enforce the zone boundary, so compromise of any host on the same "
            f"segment is equivalent to control-zone access. Correlated weaknesses "
            f"({len(state.correlations)} finding(s), worst severity {severity}) should be scoped to the "
            f"conduit and scored against the asset's target SL (SL-T) rather than as generic IT risk.")
        worst_ids = [f.check_id for f in ctx.findings
                     if f.status == "fail" and f.severity == severity]
        ctx.add(Result("ICS-08", "Risk classification", "info", severity=severity,
                       description=(f"Worst observed condition: {severity}"
                                    + (f" (CVSS {score})" if score else "")
                                    + f", from {', '.join(worst_ids) if worst_ids else 'no failing check'}. "
                                    + rationale),
                       asset=self._primary_asset(), source=state.source,
                       cvss_score=score or None,
                       cvss_vector=next((f.cvss_vector for f in ctx.findings
                                         if f.cvss_vector and f.severity == severity), None),
                       cwe=sorted({c for f in ctx.findings for c in (f.cwe or [])}),
                       remediation=("Close the correlated weaknesses in the conduit first (security "
                                    "gateway or encrypted OPC UA endpoint), then re-run this module to "
                                    "confirm the residual severity drops."),
                       evidence=[{"type": "other",
                                  "summary": "risk aggregation (IEC 62443 zone/conduit)",
                                  "worst_severity": severity, "severity_counts": counts,
                                  "worst_checks": worst_ids, "conduit": segment,
                                  "correlated_ids": [c["id"] for c in state.correlations]}],
                       data={"worst_severity": severity, "worst_cvss": score,
                             "severity_counts": counts, "failing_checks": worst_ids,
                             "iec62443": {"zone": "control-system zone (assumed)",
                                          "conduit": segment,
                                          "rationale": rationale}}))

    # ------------------------------------------------------------- ICS-09 ----
    def ics09_evidence(self, ctx: Context) -> None:
        state = self.st
        artifacts: list[dict] = []
        evidence: list[dict] = []

        transcript_lines: list[str] = [
            "# Modbus/TCP and probe transcript captured by Module C (SCADA / ICS)",
            f"# generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            f"# source: {state.source}   mode: {ctx.mode}   intensity: {ctx.intensity}",
            "# client/server libraries: raw socket (Modbus framing written by this engine)",
            "",
        ]
        for key, frames in state.modbus.items():
            transcript_lines.append(f"== endpoint {key} ==")
            for label, exchange in frames.items():
                if not isinstance(exchange, dict):
                    continue
                transcript_lines.append(format_modbus_transcript(label, exchange))
        if not state.modbus:
            transcript_lines.append("(no Modbus/TCP frame was exchanged)")
        transcript = "\n".join(transcript_lines) + "\n"
        artifacts.append(ctx.save_text("modbus_transcript.txt", transcript))

        opcua_blob = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": state.source,
            "endpoints": state.opcua,
            "confirmed": state.confirmed,
        }
        artifacts.append(ctx.save_text("opcua_endpoints.json",
                                       json.dumps(opcua_blob, indent=2, default=str)))

        summary = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "assessment_id": ctx.assessment_id,
            "module": self.module,
            "mode": ctx.mode,
            "source": state.source,
            "intensity": ctx.intensity,
            "targets": [e["target"] for e in state.eps],
            "endpoints": state.eps,
            "lab": [h.as_dict() for h in state.handles],
            "notes": state.notes,
            "tcp_probes": state.connect,
            "nmap": state.nmap,
            "segmentation": state.route,
            "operations": state.ops,
            "writes": state.writes,
            "confirmed_protocols": state.confirmed,
            "correlations": [{k: c[k] for k in ("id", "cvss", "fact")} for c in state.correlations],
        }
        artifacts.append(ctx.save_text("ics_probe_summary.json",
                                       json.dumps(summary, indent=2, default=str)))

        if state.writes:
            artifacts.append(ctx.save_text("modbus_write_cycle.json",
                                           json.dumps(state.writes, indent=2, default=str)))

        for item in artifacts:
            evidence.append(dict(item))
        first_modbus = next((f for f in state.modbus.values() if f.get("fc03")), {})
        evidence.append({"type": "protocol_frame",
                         "summary": "first Modbus request/response bytes (verbatim)",
                         "request_hex": first_modbus.get("fc03", {}).get("request_hex"),
                         "response_hex": first_modbus.get("fc03", {}).get("response_hex")})
        driver = ("pymodbus " + _version_of("pymodbus")) if HAVE_PYMODBUS else "pymodbus unavailable"
        ua_driver = ("asyncua " + _version_of("asyncua")) if HAVE_ASYNCUA else "asyncua unavailable"
        ctx.add(Result("ICS-09", "Evidence collection (raw protocol transcripts)", "info",
                       severity="info",
                       description=(f"Saved {len(artifacts)} evidence artifact(s): "
                                    + ", ".join(os.path.basename(a["path"]) for a in artifacts)
                                    + f". Transcripts hold the exact bytes received ({driver}; "
                                      f"{ua_driver})."),
                       asset=self._primary_asset(), source=state.source, evidence=evidence,
                       data={"artifacts": artifacts, "operation_count": len(state.ops),
                             "drivers": {"modbus": driver, "opcua": ua_driver}}))

    # ------------------------------------------------------------- ICS-10 ----
    def ics10_safe_stop(self, ctx: Context) -> None:
        state = self.st
        writes_allowed = bool(ctx.params.get("allow_plc_write"))
        write_done = None
        if writes_allowed and not state.writes:
            write_done = self._perform_single_write(ctx)

        used = sorted({f"{op['transport']}:{op['operation']}" for op in state.ops})
        writes = [op for op in state.ops if op["access"] != "read"]
        write_functions = sorted({f"{op['transport']}:{op['operation']}" for op in writes})
        unknown = [u for u in used
                   if u not in READ_ONLY_OPS and u not in write_functions
                   and not u.endswith(":tcp_connect")]
        staleness: list[str] = []
        own_listeners = {f"127.0.0.1:{h.port}" for h in state.handles}
        for key, probe in state.connect.items():
            if not probe.get("connected"):
                continue
            host, _, port_text = key.partition(":")
            try:
                still_open = _port_open(host, int(port_text), 0.5)
            except ValueError:
                still_open = False
            if not still_open:
                continue
            if key in own_listeners:
                staleness.append(f"{key} still answering although this run started its simulator "
                                 f"(unexpected - possible shutdown leak)")
            else:
                staleness.append(f"{key} still answering - reused or owned by another process, "
                                 f"left untouched by this run")
        lab_stopped = [f"{h.protocol}:{h.port} stop() called in run() finally"
                       for h in state.handles]

        if write_done:
            description = (
                "One documented write cycle was authorised (params.allow_plc_write=true): "
                f"{write_done['summary']}. All other operations were read-only. Functions used: "
                + ", ".join(used) + ".")
            status = "pass"
        elif writes:
            description = ("A write operation was recorded: " + ", ".join(used) + ".")
            status = "pass"
        else:
            description = (
                "The run issued READ-ONLY operations only - no register, coil or node value was "
                "modified (params.allow_plc_write is not set). Functions used: " + ", ".join(used)
                + ". Nothing requires rollback; no PLC state was changed and no device was reset.")
            status = "pass"
        if unknown:
            description += f" Operations outside the read-only allowlist: {unknown}."
            status = "info"
        if lab_stopped:
            description += " Lab simulators stopped in a finally block: " + "; ".join(lab_stopped) + "."
        if staleness:
            description += " Listeners still answering at the end of the run: " + "; ".join(staleness) + "."

        ctx.add(Result("ICS-10", "Safe-stop and rollback verification", status, severity="info",
                       description=description, asset=self._primary_asset(), source=state.source,
                       evidence=[{"type": "other",
                                  "summary": "read-only operation ledger",
                                  "operations": state.ops,
                                  "read_only_allowlist": sorted(READ_ONLY_OPS),
                                  "write_functions": write_functions,
                                  "unexpected_operations": unknown,
                                  "write_cycle": write_done,
                                  "lab_lifecycle": lab_stopped,
                                  "listeners_at_end": staleness}],
                       data={"allow_plc_write": writes_allowed,
                             "operations": state.ops,
                             "function_count": len(used),
                             "writes": write_done,
                             "write_functions": write_functions,
                             "read_only_only": not writes,
                             "unexpected_operations": unknown,
                             "lab_handles": [h.as_dict() for h in state.handles]}))

    def _perform_single_write(self, ctx: Context) -> dict | None:
        """One documented FC06 write, read-back, restore and final verified read-back."""
        state = self.st
        target = next((e for e in state.eps
                       if "modbus" in state.confirmed.get(e["key"], [])), None)
        if not target:
            return None
        unit = int(ctx.params.get("unit_id", 1))
        address = int(ctx.params.get("write_register", 0))
        before = modbus_exchange(target["host"], target["port"], unit,
                                 bytes([0x03]) + struct.pack(">HH", address, 1), timeout=2.0)
        original = parse_registers(before.get("response_hex", ""))
        if not original:
            state.note("allow_plc_write was set but the original register value could not be read; "
                       "no write was attempted")
            return None
        value = (original[0] + 1) & 0xFFFF
        write = modbus_exchange(target["host"], target["port"], unit,
                                bytes([0x06]) + struct.pack(">HH", address, value), timeout=2.0)
        state.record_op("modbus", "0x06", f"write_single_register unit={unit} addr={address} "
                                          f"value={value} (authorised)", access="write")
        readback = modbus_exchange(target["host"], target["port"], unit,
                                   bytes([0x03]) + struct.pack(">HH", address, 1), timeout=2.0)
        state.record_op("modbus", "0x03", f"read-back after write addr={address}")
        restore = modbus_exchange(target["host"], target["port"], unit,
                                  bytes([0x06]) + struct.pack(">HH", address, original[0]),
                                  timeout=2.0)
        state.record_op("modbus", "0x06", f"restore_single_register unit={unit} addr={address} "
                                          f"value={original[0]} (rollback)", access="write")
        final = modbus_exchange(target["host"], target["port"], unit,
                                bytes([0x03]) + struct.pack(">HH", address, 1), timeout=2.0)
        restored_values = parse_registers(final.get("response_hex", ""))
        cycle = {
            "endpoint": target["url"], "unit": unit, "address": address,
            "original_value": original[0], "written_value": value,
            "read_back_after_write": parse_registers(readback.get("response_hex", "")),
            "restore_value": original[0],
            "final_read_back": restored_values,
            "restored": restored_values[:1] == [original[0]],
            "frames": {"read_before": before, "write": write, "read_back": readback,
                       "restore": restore, "read_final": final},
        }
        state.writes = cycle
        return {"summary": (f"unit {unit} register {address}: {original[0]} -> {value} -> "
                            f"{cycle['final_read_back']}, restored={cycle['restored']}"),
                "cycle": cycle}


# ------------------------------------------------------------------- helpers --
def format_modbus_transcript(label: str, exchange: dict) -> str:
    """Human-readable transcript with the exact request/response bytes."""
    lines = [f"-- {label} --"]
    if exchange.get("host"):
        lines.append(f"   target      : {exchange.get('host')}:{exchange.get('port')} "
                     f"unit={exchange.get('unit')}")
    lines.append(f"   request     : {exchange.get('request_hex') or '(none)'}")
    lines.append(f"   response    : {exchange.get('response_hex') or '(none)'}")
    if exchange.get("exception_name"):
        lines.append(f"   exception   : {exchange.get('exception_code')} "
                     f"{exchange.get('exception_name')}")
    if exchange.get("duration_ms") is not None:
        lines.append(f"   duration_ms : {exchange.get('duration_ms')}")
    if exchange.get("error"):
        lines.append(f"   error       : {exchange.get('error')}")
    lines.append("")
    return "\n".join(lines)


def format_opcua_transcript(url: str, observed: dict) -> str:
    lines = [f"-- OPC UA GetEndpoints {url} --",
             f"   connected   : {observed.get('connected')}",
             f"   identity    : {observed.get('identity')}"]
    for entry in observed.get("endpoints") or []:
        lines.append(f"   endpoint    : {entry.get('endpoint_url')}")
        lines.append(f"     policy    : {entry.get('security_policy')} "
                     f"(mode {entry.get('security_mode')})")
        lines.append(f"     tokens    : {entry.get('user_tokens')}")
        lines.append(f"     app name  : {entry.get('application_name')}  "
                     f"product: {entry.get('product_uri')}")
    if observed.get("error"):
        lines.append(f"   error       : {observed.get('error')}")
    lines.append("")
    return "\n".join(lines)


def sev_name(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _version_of(package: str) -> str:
    try:
        from importlib import metadata
        return metadata.version(package)
    except Exception:
        return "unknown"
