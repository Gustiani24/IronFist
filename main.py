# IronFist — Encrypted tunnel and exit-node registry for EVM-aligned private routing.
# Gatekeeper registers exit nodes; users open tunnels and bind sessions; traffic is routed via exit nodes.
# Domain: 0xe5c1d4f7a0b3c6e9d2f5a8b1c4e7d0f3a6b9c2e5f8

from __future__ import annotations

import hashlib
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# -----------------------------------------------------------------------------
# ERRORS (unique codes; not used in other contracts)
# -----------------------------------------------------------------------------

class IFError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


# -----------------------------------------------------------------------------
# CONSTANTS (unique)
# -----------------------------------------------------------------------------

IF_MAX_TUNNELS = 256
IF_MAX_EXIT_NODES = 48
IF_MAX_SESSIONS_PER_TUNNEL = 64
IF_VIEW_BATCH = 32
IF_NAMESPACE_HEX = "0xe5c1d4f7a0b3c6e9d2f5a8b1c4e7d0f3a6b9c2e5f8"
IF_VERSION = "1.2.0"
IF_CHAIN_ID = "0x7f3c"
IF_ZERO_ADDR = "0x0000000000000000000000000000000000000000"
IF_BPS_DENOM = 10_000
IF_MAX_REGION_LEN = 8
IF_MAX_LABEL_LEN = 64
IF_RELAY_HEX = "0xd4b0e3f6a9c2d5e8b1f4a7c0d3e6f9a2b5c8d1e4f7"
IF_EST_GAS_REGISTER_NODE = 95_000
IF_EST_GAS_OPEN_TUNNEL = 78_000
IF_EST_GAS_BIND_SESSION = 65_000
IF_EST_GAS_CLOSE_TUNNEL = 52_000
IF_EST_GAS_PAUSE = 35_000
IF_EST_GAS_RESUME = 35_000

# -----------------------------------------------------------------------------
# ADDRESS VALIDATION (EVM-style)
# -----------------------------------------------------------------------------

_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

def _is_valid_address(addr: Optional[str]) -> bool:
    return addr is not None and bool(_EVM_ADDRESS_RE.match(addr.strip()))

def _normalize_address(addr: Optional[str]) -> str:
    if addr is None:
        return IF_ZERO_ADDR
    s = addr.strip()
    if s.lower().startswith("0x"):
