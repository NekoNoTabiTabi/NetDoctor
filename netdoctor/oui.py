"""Vendor lookup: map MAC-address prefixes (OUI) to vendor names.

The table is intentionally small - it holds widely used prefixes so the
feature works offline with no extra files. It is NOT the full IEEE registry;
unknown prefixes return "Unknown". Extend ``OUI_TABLE`` or load the IEEE
list if complete coverage is needed.
"""

from __future__ import annotations

from typing import Optional

OUI_TABLE = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox", "00:15:5D": "Microsoft Hyper-V",
    "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading", "28:CD:C1": "Raspberry Pi Trading",
    "00:00:0C": "Cisco Systems", "00:03:93": "Apple", "00:0A:95": "Apple",
}


def lookup_vendor(mac: Optional[str]) -> str:
    """Return the vendor for ``mac``, or a descriptive fallback."""
    if not mac:
        return "Unknown"
    parts = mac.replace("-", ":").upper().split(":")
    if len(parts) != 6:
        return "Unknown"
    try:
        first_octet = int(parts[0], 16)
    except ValueError:
        return "Unknown"
    prefix = ":".join(p.zfill(2) for p in parts[:3])
    if prefix in OUI_TABLE:
        return OUI_TABLE[prefix]
    # Bit 1 of the first octet = "locally administered": phones and laptops
    # use random MACs on Wi-Fi, so no vendor can be derived from the prefix.
    if first_octet & 0x02:
        return "Private/randomized address"
    return "Unknown"
