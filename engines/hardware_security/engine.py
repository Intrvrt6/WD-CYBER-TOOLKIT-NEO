"""Module I - Hardware Security.

Real host hardware facts only: /sys/class/*, /proc, psutil, and lsusb/lspci when
they exist.  Nothing is inferred: if this host exposes no USB subsystem, no PCI
bus, no DMI table and no EFI variables - which is the normal case inside a
container - the engine says exactly that, lists what it probed, and never
pretends to have inventoried hardware it cannot see.

Firmware integrity is reported as a FINGERPRINT, not a verification: without a
vendor baseline there is nothing to compare against, so the result states
"baseline not available" unless params["firmware_baseline"] supplies one, in
which case the comparison is real.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import platform
import re
import socket
import struct
from typing import Any

import psutil

from backend import runner
from engines import base
from engines.base import Context, Result, artifact, have, unavailable

SYS = "/sys"
FW_CANDIDATES = [
    "/sys/class/dmi/id/bios_vendor", "/sys/class/dmi/id/bios_version", "/sys/class/dmi/id/bios_date",
    "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/board_name", "/sys/class/dmi/id/board_version",
    "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/product_version", "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/chassis_vendor", "/sys/class/dmi/id/chassis_type",
    "/sys/devices/system/cpu/microcode/version",
    "/proc/version", "/proc/cmdline",
]
HASH_LIMIT_BYTES = 1 << 20     # 1 MiB per file
HASH_MAX_FILES = 32


class HardwareEngine:
    module = "hardware_security"
    title = "Module I - Hardware Security"
    description = ("Host hardware inventory from sysfs/procfs, peripheral identification, firmware fingerprinting, "
                   "NIC/USB/disk anomaly heuristics, authorised-device diffing and tamper-evidence review.")
    checks = [
        ("HW-01", "USB inventory", True),
        ("HW-02", "Peripheral identification", True),
        ("HW-03", "Firmware integrity assessment", True),
        ("HW-04", "Device inventory", True),
        ("HW-05", "Hardware anomaly detection", True),
        ("HW-06", "Unauthorized device detection", True),
        ("HW-07", "Tamper evidence inspection", True),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        self._ctx_info = container_facts()
        steps = [("HW-01", self.usb_inventory), ("HW-02", self.peripherals),
                 ("HW-03", self.firmware), ("HW-04", self.device_inventory),
                 ("HW-05", self.anomalies), ("HW-06", self.unauthorized),
                 ("HW-07", self.tamper_evidence)]
        for i, (cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("HW-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining hardware checks were not executed.", source="local"))
                break
            try:
                fn(ctx)
            except Exception as exc:
                ctx.add(Result(f"{cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ------------------------------------------------------------ HW-01 ----
    def usb_inventory(self, ctx: Context) -> None:
        devices = usb_devices()
        probed = {
            "/sys/bus/usb/devices": os.path.isdir("/sys/bus/usb/devices"),
            "/dev/bus/usb": os.path.isdir("/dev/bus/usb"),
            "lsusb": have("lsusb"),
        }
        lsusb_out = None
        if have("lsusb"):
            res = runner.run(["lsusb"], timeout=15)
            lsusb_out = (res.stdout or res.stderr or "").strip()
        if not devices:
            reason = ("No USB device could be enumerated on this host. Probed: "
                      f"/sys/bus/usb/devices present={probed['/sys/bus/usb/devices']}, "
                      f"/dev/bus/usb present={probed['/dev/bus/usb']}, "
                      f"lsusb installed={probed['lsusb']}. Environment: {self._ctx_info['kind']} "
                      f"({'; '.join(self._ctx_info['markers']) or 'no container marker'}); "
                      f"/sys/firmware entries={self._ctx_info.get('sys_firmware_entries') or 'none'}, "
                      f"DMI table present={self._ctx_info['dmi_present']}, PCI bus present={self._ctx_info['pci_present']}. "
                      "USB inventory therefore requires a host with a USB controller exposed (bare metal, or a VM "
                      "with USB passthrough).")
            ctx.add(Result("HW-01", "USB inventory", "unavailable", severity="info",
                           description=reason, asset=socket.gethostname(), source="unavailable",
                           evidence=[{"type": "other", "summary": "USB enumeration sources probed",
                                      "probed": probed,
                                      "lsusb_output": lsusb_out,
                                      "container": self._ctx_info}],
                           data={"devices": [], "probed": probed, "lsusb": lsusb_out,
                                 "container": self._ctx_info}))
            return
        evidence: list[dict] = [{"type": "other", "summary": "sysfs usb devices", "devices": devices}]
        if lsusb_out:
            evidence.append({"type": "command_output", "command": "lsusb", "stdout": lsusb_out})
        no_serial = [d for d in devices if not d.get("serial")]
        ctx.add(Result("HW-01", "USB inventory", "info",
                       description=(f"Enumerated {len(devices)} USB device(s) from /sys/bus/usb/devices; "
                                    f"{len(no_serial)} expose no serial descriptor. /dev/bus/usb "
                                    f"{'present' if probed['/dev/bus/usb'] else 'absent'}; lsusb "
                                    f"{'used' if lsusb_out else 'not available'}."),
                       asset=socket.gethostname(), source="local", evidence=evidence,
                       data={"devices": devices, "probed": probed, "no_serial": no_serial}))

    # ------------------------------------------------------------ HW-02 ----
    def peripherals(self, ctx: Context) -> None:
        pci = pci_devices()
        inputs = input_devices()
        disks = block_devices()
        nics = nic_devices()
        lspci_out = None
        if have("lspci"):
            r = runner.run(["lspci", "-nn"], timeout=15)
            lspci_out = (r.stdout or "").strip()
        present = {"pci_sysfs": bool(pci), "lspci": bool(lspci_out), "input_sysfs": bool(inputs),
                   "block_sysfs": bool(disks), "net_sysfs": bool(nics)}
        missing = [k for k, v in present.items() if not v]
        desc = (f"Peripheral sources that yielded data: "
                + (", ".join(f"{k}={len(v)}" for k, v in (("pci", pci), ("input", inputs),
                                                          ("block", disks), ("net", nics))) or "none")
                + (f". Sources with no data on this host: {', '.join(missing)}." if missing else "."))
        ctx.add(Result("HW-02", "Peripheral identification", "info", description=desc,
                       asset=socket.gethostname(), source="local",
                       evidence=[{"type": "other", "summary": "peripheral inventory",
                                  "pci": pci, "input": inputs, "block": disks, "net": nics,
                                  "lspci": lspci_out, "container": self._ctx_info}],
                       data={"pci": pci, "input": inputs, "block": disks, "net": nics,
                             "lspci_available": bool(lspci_out), "sources": present,
                             "container": self._ctx_info}))

    # ------------------------------------------------------------ HW-03 ----
    def firmware(self, ctx: Context) -> None:
        dmi: dict[str, Any] = {}
        for key in ("bios_vendor", "bios_version", "bios_date", "board_vendor", "board_name",
                    "product_name", "product_version", "sys_vendor", "chassis_vendor", "chassis_type"):
            val = read_text(f"/sys/class/dmi/id/{key}")
            if val is not None:
                dmi[key] = val
        efi = {
            "efi_sysfs": os.path.isdir("/sys/firmware/efi"),
            "efivars": os.path.isdir("/sys/firmware/efi/efivars"),
            "firmware_dir_entries": sorted(os.listdir("/sys/firmware")) if os.path.isdir("/sys/firmware") else [],
        }
        microcode = read_text("/sys/devices/system/cpu/microcode/version")
        files = firmware_fingerprint()
        baseline = ctx.params.get("firmware_baseline")
        comparison: dict[str, Any] = {"supplied": baseline is not None}
        if isinstance(baseline, str) and os.path.exists(baseline):
            try:
                baseline = json.load(open(baseline, encoding="utf-8"))
            except Exception as exc:
                comparison["baseline_error"] = f"baseline file unreadable: {exc}"
        if isinstance(baseline, dict):
            base_files = baseline.get("files") or {}
            matched, mismatched, missing = [], [], []
            for name, digest in base_files.items():
                cur = files.get(name)
                if cur is None:
                    missing.append(name)
                elif cur == digest:
                    matched.append(name)
                else:
                    mismatched.append({"file": name, "expected": digest, "observed": cur})
            comparison.update({"matched": matched, "mismatched": mismatched, "missing": missing,
                               "baseline_digest": baseline.get("combined"), "observed_digest": files.get("__combined__")})
            verified = not mismatched and not missing and bool(base_files)
            ctx.add(Result(
                "HW-03", "Firmware integrity assessment", "pass" if verified else "fail",
                severity="high" if mismatched else ("medium" if missing else "info"),
                description=(f"Compared {len(base_files)} baseline firmware file hash(es) against the live host: "
                             f"{len(matched)} match, {len(mismatched)} differ, {len(missing)} unavailable. "
                             + ("Firmware matches the supplied baseline." if verified else
                                "Deviation from the supplied vendor baseline observed.")),
                asset=socket.gethostname(), source="local",
                cvss_score=7.2 if mismatched else (3.7 if missing else None),
                cwe=["CWE-345"] if mismatched else [],
                remediation=("Re-flash the vendor firmware image and re-baseline after verification." if not verified
                             else "No action required: the observed firmware matches the supplied baseline."),
                evidence=[{"type": "other", "summary": "baseline comparison", "comparison": comparison,
                           "dmi": dmi, "efi": efi, "microcode": microcode}],
                data={"comparison": comparison, "dmi": dmi, "efi": efi, "microcode": microcode,
                      "fingerprint_files": {k: v for k, v in files.items() if k != "__combined__"},
                      "combined_digest": files.get("__combined__")}))
            return

        reason = ("baseline not available: no params.firmware_baseline hash was supplied, so the observed "
                  "firmware fingerprint cannot be verified against a vendor baseline. This is a fingerprint, "
                  "not an integrity verdict.")
        detail_bits = []
        if dmi:
            detail_bits.append("DMI readable: " + ", ".join(f"{k}={v}" for k, v in list(dmi.items())[:6]))
        else:
            detail_bits.append(f"no /sys/class/dmi/id/* entries are readable on this host ({self._ctx_info['kind']})")
        detail_bits.append("/sys/firmware/efi " + ("present" if efi["efi_sysfs"] else "absent (legacy/BIOS boot "
                                                                                      "or not exposed)"))
        detail_bits.append(f"microcode version {'readable: ' + microcode if microcode else 'not exposed'}")
        detail_bits.append(f"hashed {len([k for k in files if k != '__combined__'])} readable firmware-ish file(s)")
        ctx.add(Result(
            "HW-03", "Firmware integrity assessment", "info", severity="info",
            description=reason + " Observed: " + "; ".join(detail_bits) + ".",
            asset=socket.gethostname(), source="local",
            evidence=[{"type": "other", "summary": "firmware fingerprint (unverified)",
                       "dmi": dmi, "efi": efi, "microcode": microcode,
                       "files": {k: v for k, v in files.items() if k != "__combined__"},
                       "combined_digest": files.get("__combined__"), "container": self._ctx_info}],
            data={"baseline": "not available", "dmi": dmi, "efi": efi, "microcode": microcode,
                  "files": {k: v for k, v in files.items() if k != "__combined__"},
                  "combined_digest": files.get("__combined__"),
                  "expected_baseline_format": {"files": {"<path>": "<sha256>"}, "combined": "<sha256>"},
                  "container": self._ctx_info}))

    # ------------------------------------------------------------ HW-04 ----
    def device_inventory(self, ctx: Context) -> None:
        cpu = cpu_facts()
        mem = psutil.virtual_memory()
        disks = block_devices()
        parts = [{"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype, "opts": p.opts}
                 for p in psutil.disk_partitions(all=False)]
        nics = nic_devices()
        usb = usb_devices()
        pci = pci_devices()
        ctx.add(Result(
            "HW-04", "Device inventory", "info",
            description=(f"Aggregate host inventory: {cpu.get('logical', '?')} logical CPU(s) "
                         f"({cpu.get('model', 'unknown model')}), {mem.total / 2**30:.1f} GiB RAM, "
                         f"{len(disks)} block device(s) / {len(parts)} mounted partition(s), {len(nics)} network "
                         f"interface(s), {len(usb)} USB device(s), {len(pci)} PCI device(s). "
                         f"Platform: {platform.platform()}."),
            asset=socket.gethostname(), source="local",
            evidence=[{"type": "other", "summary": "aggregate inventory",
                       "cpu": cpu, "memory": {"total": mem.total, "available": mem.available},
                       "disks": disks, "partitions": parts, "nics": nics, "usb": usb, "pci": pci,
                       "container": self._ctx_info}],
            data={"cpu": cpu, "memory_total_bytes": mem.total, "memory_available_bytes": mem.available,
                  "disks": disks, "partitions": parts, "nics": nics, "usb": usb, "pci": pci,
                  "platform": platform.platform(), "hostname": socket.gethostname(),
                  "container": self._ctx_info, "boot_time": psutil.boot_time()}))

    # ------------------------------------------------------------ HW-05 ----
    def anomalies(self, ctx: Context) -> None:
        findings: list[dict] = []
        heuristics = [
            "NIC MAC with the locally-administered bit set (0x02 in the first octet) while addr_assign_type "
            "indicates a permanent address",
            "NIC MAC that is a multicast address (0x01 in the first octet)",
            "PCI device present with no kernel driver bound",
            "USB device exposing no serial descriptor",
            "Block device with no model/serial exposing no SMART interface (smartctl absent)",
        ]
        for nic in nic_devices():
            mac = nic.get("mac") or ""
            first = mac.split(":")[0] if ":" in mac else ""
            try:
                octet = int(first, 16)
            except ValueError:
                octet = None
            if octet is not None and octet & 0x02 and octet & 0x01 == 0:
                assign = nic.get("addr_assign_type")
                permanent = str(assign) == "0"
                findings.append({
                    "type": "locally-administered-mac", "iface": nic["name"], "mac": mac,
                    "addr_assign_type": assign, "detail":
                        f"{nic['name']} uses the locally-administered MAC {mac}"
                        + (f" while addr_assign_type=0 reports it as permanent" if permanent
                           else f" (addr_assign_type={assign}: 1=random, 2=stolen, 3=set)")
                        + "; verify against the physical NIC inventory - veth/bridge interfaces normally "
                          "carry a locally-administered address",
                    # A locally-administered MAC alone is a prompt to verify, not proof of tampering.
                    "severity": "low"})
            if octet is not None and octet & 0x01:
                findings.append({"type": "multicast-mac", "iface": nic["name"], "mac": mac,
                                 "detail": f"{nic['name']} has a multicast MAC {mac}", "severity": "high"})
        for dev in pci_devices():
            if not dev.get("driver"):
                findings.append({"type": "pci-no-driver", "device": dev["slot"],
                                 "detail": f"PCI {dev['slot']} ({dev.get('vendor')}:{dev.get('device')}) has no "
                                           f"driver symlink under /sys/bus/pci/devices/",
                                 "severity": "low"})
        for dev in usb_devices():
            if not dev.get("serial"):
                findings.append({"type": "usb-no-serial", "device": dev.get("idVendor", "") + ":" + dev.get("idProduct", ""),
                                 "detail": f"USB {dev.get('manufacturer') or '?'} {dev.get('product') or '?'} "
                                           f"({dev.get('idVendor')}:{dev.get('idProduct')}) exposes no serial",
                                 "severity": "low"})
        smart = have("smartctl")
        for disk in block_devices():
            if disk.get("removable") in ("1", True):
                findings.append({"type": "removable-disk", "device": disk["name"],
                                 "detail": f"{disk['name']} is marked removable", "severity": "low"})
            # Loop/ram pseudo-devices have no hardware identity by design; only
            # real block devices are checked for identity/SMART coverage.
            if disk.get("virtual") or disk["name"].startswith(("loop", "ram", "zram")):
                continue
            if not smart and not disk.get("model") and not disk.get("serial"):
                findings.append({"type": "no-smart-no-identity", "device": disk["name"],
                                 "detail": f"{disk['name']} exposes neither model nor serial in sysfs and smartctl "
                                           f"is not installed, so its identity/SMART health cannot be established",
                                 "severity": "info"})
        observed = [f for f in findings if f["severity"] in ("medium", "high")]
        weak = [f for f in findings if f["severity"] == "low"]
        ctx.add(Result(
            "HW-05", "Hardware anomaly detection", "fail" if observed else "info",
            severity="medium" if observed else ("low" if weak else "info"),
            description=(f"Applied {len(heuristics)} stated heuristics; {len(findings)} match(es) observed "
                         f"({len(observed)} at medium/high severity). Matches: "
                         + ("; ".join(f"{f['type']} on {f.get('iface') or f.get('device')}" for f in findings[:8])
                            or "none") + "."),
            asset=socket.gethostname(), source="local",
            cvss_score=4.3 if observed else None, cwe=["CWE-1188"] if observed else [],
            remediation=("Confirm the interface MAC against the hardware inventory; a permanent NIC reporting a "
                         "locally-administered address indicates a spoofed/overridden MAC." if observed else
                         ("Review each low-severity match with the hardware owner; locally-administered MACs are "
                          "normal on virtual/bridge interfaces, so they are reported for verification, not as "
                          "findings. Re-run on the physical host for USB/PCI/SMART coverage." if weak else
                          "Re-run on the physical host to obtain USB/PCI/SMART coverage.")),
            evidence=[{"type": "other", "summary": "anomaly heuristics applied",
                       "heuristics": heuristics, "matches": findings, "smartctl_available": smart,
                       "container": self._ctx_info}],
            data={"heuristics": heuristics, "matches": findings,
                  "matched_types": sorted({f["type"] for f in findings}),
                  "smartctl_available": smart,
                  "coverage_note": ("USB/PCI/SMART heuristics produced no matches because those subsystems are "
                                    "not exposed in this environment." if not (pci_devices() or usb_devices() or smart)
                                    else "all heuristics had the data they need"),
                  "container": self._ctx_info}))

    # ------------------------------------------------------------ HW-06 ----
    def unauthorized(self, ctx: Context) -> None:
        usb = usb_devices()
        pci = pci_devices()
        disks = block_devices()
        inventory = []
        for d in usb:
            inventory.append({"kind": "usb", "key": f"{d.get('idVendor')}:{d.get('idProduct')}",
                              "serial": d.get("serial"), "name": d.get("product")})
        for d in pci:
            inventory.append({"kind": "pci", "key": f"{d.get('vendor')}:{d.get('device')}",
                              "slot": d["slot"], "name": d.get("driver")})
        for d in disks:
            if d.get("virtual") or d["name"].startswith(("loop", "ram", "zram")):
                continue  # pseudo-devices carry no hardware identity to authorise
            inventory.append({"kind": "disk", "key": d.get("serial") or d["name"],
                              "name": d["name"], "serial": d.get("serial"),
                              "model": d.get("model")})
        allowed = ctx.params.get("authorized_inventory")
        if allowed is None:
            ctx.add(Result(
                "HW-06", "Unauthorized device detection", "info", severity="info",
                description=("Baseline captured: "
                             f"{len(inventory)} device identifier(s) observed ({len(usb)} USB, {len(pci)} PCI, "
                             f"{len(disks)} disk). Comparison was NOT possible because params.authorized_inventory "
                             "was not supplied - without an authorised list there is nothing to diff against, and "
                             "reporting devices as 'unauthorized' would be fabrication."),
                asset=socket.gethostname(), source="local",
                evidence=[{"type": "other", "summary": "captured baseline", "inventory": inventory,
                           "container": self._ctx_info}],
                data={"baseline": inventory, "compared": False,
                      "reason": "params.authorized_inventory not supplied",
                      "expected_format": ["vendor:product", "serial", {"key": "...", "kind": "usb|pci|disk"}],
                      "container": self._ctx_info}))
            return
        allow_keys, allow_serials = normalise_authorized(allowed)
        allowed_all = allow_keys | allow_serials
        unknown, matched = [], []
        for item in inventory:
            ids = {(item.get("key") or "").lower(), (item.get("serial") or "").lower(),
                   (item.get("name") or "").lower()} - {""}
            if ids & allowed_all:
                matched.append(item)
            else:
                unknown.append(item)
        ctx.add(Result(
            "HW-06", "Unauthorized device detection", "fail" if unknown else "pass",
            severity="medium" if unknown else "info",
            description=(f"Diffed {len(inventory)} observed device identifier(s) against "
                         f"{len(allow_keys)} allowed key(s) and {len(allow_serials)} allowed serial(s): "
                         f"{len(matched)} authorised, {len(unknown)} not in the authorised inventory"
                         + (": " + "; ".join(f"{u['kind']} {u.get('key') or u.get('name')}" for u in unknown[:10])
                            if unknown else "") + "."),
            asset=socket.gethostname(), source="local",
            cvss_score=5.5 if unknown else None, cwe=["CWE-1263"] if unknown else [],
            remediation=("Physically verify each unmatched device, then either authorise it in the inventory or "
                         "remove it." if unknown else
                         "No unlisted device observed; refresh the authorised inventory at each hardware change."),
            evidence=[{"type": "other", "summary": "authorised-inventory diff",
                       "inventory": inventory, "allowed_keys": sorted(allow_keys)[:100],
                       "allowed_serials": sorted(allow_serials)[:100],
                       "unauthorized": unknown, "matched": matched}],
            data={"compared": True, "observed": len(inventory), "authorized": matched,
                  "unauthorized": unknown, "allowed_keys": sorted(allow_keys)[:200],
                  "allowed_serials": sorted(allow_serials)[:200]}))

    # ------------------------------------------------------------ HW-07 ----
    def tamper_evidence(self, ctx: Context) -> None:
        intrusion: dict[str, Any] = {}
        for key in ("chassis_type", "chassis_vendor", "chassis_version", "chassis_serial", "chassis_asset_tag"):
            val = read_text(f"/sys/class/dmi/id/{key}")
            if val is not None:
                intrusion[key] = val
        secure_boot = read_efi_var("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        setup_mode = read_efi_var("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        tpm = {"tpm_sysfs": os.path.isdir("/sys/class/tpm"),
               "tpm_dev": sorted(glob.glob("/dev/tpm*")),
               "tpm_version": read_text("/sys/class/tpm/tpm0/tpm_version_major")}
        host_items = [
            {"id": "HW-TE-01", "item": "Chassis intrusion switch reported by firmware",
             "observable": "host" if intrusion else "on-site-only",
             "result": ("DMI chassis fields read: " + ", ".join(f"{k}={v}" for k, v in intrusion.items()))
             if intrusion else "no /sys/class/dmi/id/chassis_* readable - physical inspection required"},
            {"id": "HW-TE-02", "item": "UEFI Secure Boot enabled",
             "observable": "host" if secure_boot is not None else "on-site-only",
             "result": f"SecureBoot EFI variable = {secure_boot}" if secure_boot is not None
             else "SecureBoot EFI variable not readable (no EFI runtime in this environment)"},
            {"id": "HW-TE-03", "item": "Firmware setup mode disabled (no unauthenticated key enrolment)",
             "observable": "host" if setup_mode is not None else "on-site-only",
             "result": f"SetupMode EFI variable = {setup_mode}" if setup_mode is not None
             else "SetupMode EFI variable not readable"},
            {"id": "HW-TE-04", "item": "Discrete TPM present and enabled",
             "observable": "host" if (tpm["tpm_sysfs"] or tpm["tpm_dev"]) else "on-site-only",
             "result": f"/sys/class/tpm present={tpm['tpm_sysfs']}, devices={tpm['tpm_dev'] or 'none'}"},
            {"id": "HW-TE-05", "item": "Case screws / tamper seals intact", "observable": "on-site-only",
             "result": "requires on-site inspection; no host signal exists for case seals"},
            {"id": "HW-TE-06", "item": "Unused external ports physically blocked", "observable": "on-site-only",
             "result": "requires on-site inspection"},
            {"id": "HW-TE-07", "item": "No unexpected USB devices attached", "observable": "host",
             "result": (f"{len(usb_devices())} USB device(s) enumerated" if usb_devices()
                        else "USB subsystem not exposed to this process; see HW-01")},
            {"id": "HW-TE-08", "item": "Boot order / removable boot disabled", "observable": "on-site-only",
             "result": "requires firmware setup access; not readable from the running OS"},
        ]
        host_checked = [i for i in host_items if i["observable"] == "host" and
                        not i["result"].startswith(("no ", "not ", "requires"))]
        on_site = [i for i in host_items if i["observable"] == "on-site-only"]
        art = ctx.save_text("hardware_tamper_checklist.json",
                            json.dumps({"generated_at_host": socket.gethostname(),
                                        "items": host_items}, indent=2))
        ctx.add(Result(
            "HW-07", "Tamper evidence inspection", "info",
            description=(f"{len(host_items)} tamper-relevant item(s): {len(host_items) - len(on_site)} "
                         f"host-observable, {len(on_site)} on-site-only. Host signals that actually returned data: "
                         f"{len(host_checked)} of {len(host_items) - len(on_site)} "
                         f"({', '.join(i['id'] for i in host_checked) or 'none'}). "
                         f"On-site items require physical operator input and are NOT reported as assessed."),
            asset=socket.gethostname(), source="local",
            evidence=[art, {"type": "other", "summary": "tamper items and observability",
                            "items": host_items, "secure_boot": secure_boot, "setup_mode": setup_mode,
                            "dmi_chassis": intrusion, "tpm": tpm, "container": self._ctx_info}],
            data={"items": host_items, "host_observable": len(host_items) - len(on_site),
                  "on_site_only": [i["id"] for i in on_site],
                  "host_signals_observed": [i["id"] for i in host_checked],
                  "secure_boot": secure_boot, "setup_mode": setup_mode,
                  "dmi_chassis": intrusion, "tpm": tpm,
                  "checklist_artifact": art["path"], "container": self._ctx_info}))


# ------------------------------------------------------------- collection --
def read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def container_facts() -> dict:
    markers = []
    if os.path.exists("/.dockerenv"):
        markers.append("/.dockerenv present")
    if os.path.exists("/run/.containerenv"):
        markers.append("/run/.containerenv present")
    cgroup = read_text("/proc/1/cgroup") or ""
    for token in ("docker", "kubepods", "containerd", "lxc"):
        if token in cgroup:
            markers.append(f"/proc/1/cgroup contains '{token}'")
    virt = None
    if have("systemd-detect-virt"):
        r = runner.run(["systemd-detect-virt"], timeout=8)
        out = (r.stdout or "").strip()
        if out and out != "none":
            virt = out
    dmi_present = os.path.isdir("/sys/class/dmi/id")
    pci_present = os.path.isdir("/sys/bus/pci/devices")
    fw_entries = sorted(os.listdir("/sys/firmware")) if os.path.isdir("/sys/firmware") else []
    if markers:
        kind = "container"
    elif virt:
        kind = f"virtual-machine ({virt})"
    elif not dmi_present and not pci_present:
        kind = "restricted/virtualised view (no DMI table, no PCI bus)"
    else:
        kind = "physical-or-unknown"
    return {"in_container": bool(markers), "markers": markers, "kind": kind,
            "virtualization": virt, "dmi_present": dmi_present, "pci_present": pci_present,
            "sys_firmware_entries": fw_entries,
            "dmi_product_name": read_text("/sys/class/dmi/id/product_name"),
            "pid1": (read_text("/proc/1/comm") or "")}


def usb_devices() -> list[dict]:
    base = "/sys/bus/usb/devices"
    out: list[dict] = []
    if not os.path.isdir(base):
        return out
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for name in entries:
        path = os.path.join(base, name)
        vendor = read_text(os.path.join(path, "idVendor"))
        product = read_text(os.path.join(path, "idProduct"))
        if not vendor or not product:
            continue  # interfaces (e.g. 1-1:1.0) carry no ids
        out.append({
            "sysfs": name, "idVendor": vendor, "idProduct": product,
            "manufacturer": read_text(os.path.join(path, "manufacturer")),
            "product": read_text(os.path.join(path, "product")),
            "serial": read_text(os.path.join(path, "serial")),
            "bDeviceClass": read_text(os.path.join(path, "bDeviceClass")),
            "busnum": read_text(os.path.join(path, "busnum")),
            "devnum": read_text(os.path.join(path, "devnum")),
            "speed": read_text(os.path.join(path, "speed")),
        })
    return out


def pci_devices() -> list[dict]:
    base = "/sys/bus/pci/devices"
    out: list[dict] = []
    if not os.path.isdir(base):
        return out
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for slot in entries:
        path = os.path.join(base, slot)
        out.append({
            "slot": slot,
            "vendor": read_text(os.path.join(path, "vendor")),
            "device": read_text(os.path.join(path, "device")),
            "class": read_text(os.path.join(path, "class")),
            "driver": os.path.basename(os.path.realpath(os.path.join(path, "driver")))
            if os.path.exists(os.path.join(path, "driver")) else None,
        })
    return out


def input_devices() -> list[dict]:
    base = "/sys/class/input"
    out: list[dict] = []
    if not os.path.isdir(base):
        return out
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for name in entries:
        if not name.startswith("input"):
            continue
        path = os.path.join(base, name)
        out.append({"name": name, "device": read_text(os.path.join(path, "name")),
                    "phys": read_text(os.path.join(path, "phys"))})
    return out


def block_devices() -> list[dict]:
    base = "/sys/class/block"
    out: list[dict] = []
    if not os.path.isdir(base):
        return out
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for name in entries:
        path = os.path.join(base, name)
        size_sectors = read_text(os.path.join(path, "size"))
        try:
            size_bytes = int(size_sectors) * 512 if size_sectors else 0
        except ValueError:
            size_bytes = 0
        out.append({
            "name": name, "size_bytes": size_bytes,
            "removable": read_text(os.path.join(path, "removable")),
            "ro": read_text(os.path.join(path, "ro")),
            "model": read_text(os.path.join(path, "device/model")),
            "vendor": read_text(os.path.join(path, "device/vendor")),
            "serial": read_text(os.path.join(path, "device/serial")) or read_text(os.path.join(path, "serial")),
            "virtual": not os.path.exists(os.path.join(path, "device")),
        })
    return out


def nic_devices() -> list[dict]:
    base = "/sys/class/net"
    out: list[dict] = []
    if not os.path.isdir(base):
        return out
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for name in entries:
        path = os.path.join(base, name)
        driver_link = os.path.join(path, "device/driver")
        module_link = os.path.join(path, "device/driver/module")
        out.append({
            "name": name,
            "mac": read_text(os.path.join(path, "address")),
            "addr_assign_type": read_text(os.path.join(path, "addr_assign_type")),
            "operstate": read_text(os.path.join(path, "operstate")),
            "mtu": read_text(os.path.join(path, "mtu")),
            "driver": os.path.basename(os.path.realpath(driver_link)) if os.path.exists(driver_link) else None,
            "module": os.path.basename(os.path.realpath(module_link)) if os.path.exists(module_link) else None,
            "virtual": not os.path.exists(os.path.join(path, "device")),
        })
    return out


def cpu_facts() -> dict:
    info: dict[str, Any] = {"logical": psutil.cpu_count(), "physical": psutil.cpu_count(logical=False)}
    text = read_text("/proc/cpuinfo") or ""
    m = re.search(r"^model name\s*:\s*(.+)$", text, re.MULTILINE)
    if m:
        info["model"] = m.group(1).strip()
    v = re.search(r"^vendor_id\s*:\s*(.+)$", text, re.MULTILINE)
    if v:
        info["vendor"] = v.group(1).strip()
    flags = re.search(r"^flags\s*:\s*(.+)$", text, re.MULTILINE)
    if flags:
        wanted = {"smep", "smap", "pti", "ibrs", "ibpb", "spec_ctrl", "ssbd", "md_clear", "lm"}
        info["security_flags_present"] = sorted(wanted & set(flags.group(1).split()))
    return info


def firmware_fingerprint() -> dict[str, str]:
    files: dict[str, str] = {}
    candidates = list(FW_CANDIDATES)
    candidates += sorted(glob.glob("/sys/class/dmi/id/*"))
    candidates += sorted(glob.glob("/sys/firmware/efi/efivars/*"))[:8]
    candidates += sorted(glob.glob("/boot/vmlinuz*"))[:4] + sorted(glob.glob("/boot/config-*"))[:4]
    seen = set()
    for path in candidates:
        if path in seen or len(file_list := files) >= HASH_MAX_FILES:
            continue
        seen.add(path)
        try:
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            # procfs/sysfs report size 0 for readable files, so only reject a
            # genuinely empty regular file outside those filesystems.
            if size == 0 and not path.startswith(("/proc/", "/sys/")):
                continue
            if size > HASH_LIMIT_BYTES:
                continue
            h = hashlib.sha256()
            total = 0
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    total += len(chunk)
                    if total > HASH_LIMIT_BYTES:
                        break
                    h.update(chunk)
            if total == 0:
                continue
            files[path] = h.hexdigest()
        except OSError:
            continue
    combined = hashlib.sha256()
    for name in sorted(files):
        combined.update(name.encode())
        combined.update(files[name].encode())
    files["__combined__"] = combined.hexdigest()
    return files


def read_efi_var(name: str) -> str | None:
    path = f"/sys/firmware/efi/efivars/{name}"
    try:
        with open(path, "rb") as fh:
            blob = fh.read(8)
    except OSError:
        return None
    if len(blob) < 5:
        return None
    return str(int.from_bytes(blob[4:8], "little"))


def normalise_authorized(allowed: Any) -> tuple[set[str], set[str]]:
    keys: set[str] = set()
    serials: set[str] = set()
    items = allowed if isinstance(allowed, (list, tuple, set)) else [allowed]
    for entry in items:
        if isinstance(entry, dict):
            for k in ("key", "serial", "vendor_product", "id"):
                if entry.get(k):
                    (serials if k == "serial" else keys).add(str(entry[k]).strip().lower())
            if entry.get("vendor") and entry.get("product"):
                keys.add(f"{entry['vendor']}:{entry['product']}".lower())
        elif isinstance(entry, str):
            low = entry.strip().lower()
            if ":" in low:
                keys.add(low)
            else:
                serials.add(low)
    return keys, serials
