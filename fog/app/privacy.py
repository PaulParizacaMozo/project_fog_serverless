from __future__ import annotations
from typing import Any, Dict


_PII_KEYS = {
    "srcip", "dstip", "sport", "dsport",
    "SrcIP", "DstIP", "Sport", "Dport",
    "src_ip", "dst_ip", "src_port", "dst_port"
}


def strip_pii(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enforce: jamás imprimimos / propagamos IPs o puertos.
    Si llegan por accidente, los eliminamos.
    """
    clean = {}
    for k, v in record.items():
        if k in _PII_KEYS:
            continue
        # también limpia nested dicts si existieran
        if isinstance(v, dict):
            clean[k] = strip_pii(v)
        else:
            clean[k] = v
    return clean

