"""Tiny offline OUI (MAC vendor) table.

The full IEEE OUI registry is ~7 MB and updated daily; NetSleuth ships a
hand-picked subset of vendors common in labs and enterprise networks
(hypervisors, SoHo routers, big OEMs) instead of vendoring the whole
database. Unknown prefixes simply report no vendor.
"""

from __future__ import annotations

OUI: dict[str, str] = {
    "00:00:0c": "Cisco", "00:01:6c": "IBM", "00:0c:29": "VMware",
    "00:0d:3a": "Microsoft Azure", "00:11:32": "Synology", "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen", "00:1e:58": "D-Link", "00:22:19": "Dell",
    "00:24:e8": "Dell", "00:40:96": "Cisco", "00:50:56": "VMware",
    "00:a0:c9": "Intel", "00:e0:4c": "Realtek", "01:00:5e": "IPv4 multicast",
    "03:00:00": "Cisco PVST+", "08:00:07": "Apple", "08:00:27": "Oracle VirtualBox",
    "0c:c4:7a": "Cisco", "10:7b:44": "Cisco", "20:4c:9e": "TP-Link",
    "24:5a:4c": "Dell", "28:c2:dd": "Huawei", "30:b5:c2": "Dell",
    "3c:07:54": "Apple", "34:17:eb": "Dell EMC", "40:b0:fa": "H3C",
    "44:37:e6": "Huawei", "48:0f:cf": "H3C", "50:9a:4c": "H3C",
    "54:bf:64": "Huawei", "58:61:53": "D-Link", "58:d5:6e": "Dell",
    "5c:f9:dd": "Cisco", "60:6d:c7": "Cisco", "64:51:06": "Apple",
    "68:05:ca": "Cisco", "6c:3b:e5": "Cisco", "74:e1:b6": "Huawei",
    "80:c1:6e": "Huawei", "84:16:f9": "Huawei", "8c:ec:4b": "Huawei",
    "94:57:a5": "Dell", "98:4b:e1": "Cisco", "9c:b6:54": "Ubiquiti",
    "a4:2b:b0": "Microsoft", "a4:bb:6d": "H3C", "ac:de:48": "Apple",
    "b8:27:eb": "Raspberry Pi", "c8:3a:35": "D-Link", "cc:46:d6": "Cisco",
    "d4:6a:6a": "Dell", "d8:cb:8a": "Cisco", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "f0:18:98": "Apple", "f0:9f:c2": "Apple",
    "f8:bc:12": "H3C", "fc:fb:fb": "Cisco",
}


def vendor_lookup(mac: str) -> str:
    """Return the vendor for a MAC like '08:00:27:aa:bb:cc', or ''."""
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return OUI.get(":".join(parts[:3]), "")
    except (AttributeError, ValueError):
        return ""
