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
        return s
    return "0x" + s

# -----------------------------------------------------------------------------
# EVENTS (immutable payloads)
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class IFExitNodeRegistered:
    node_id: str
    region: str
    endpoint_hex: str
    at_block: int

@dataclass(frozen=True)
class IFTunnelOpened:
    tunnel_id: str
    owner: str
    exit_node_id: str
    at_block: int

@dataclass(frozen=True)
class IFSessionBound:
    tunnel_id: str
    session_id: str
    client: str
    at_block: int

@dataclass(frozen=True)
class IFTunnelClosed:
    tunnel_id: str
    at_block: int

@dataclass(frozen=True)
class IFNetworkPaused:
    by: str
    at_block: int

@dataclass(frozen=True)
class IFNetworkResumed:
    by: str
    at_block: int

# -----------------------------------------------------------------------------
# SAFE MATH (wei / u256 style)
# -----------------------------------------------------------------------------

def _clamp_u256(value: int) -> int:
    if value < 0:
        return 0
    max_u256 = (1 << 256) - 1
    return min(value, max_u256)

def _add_safe(a: int, b: int) -> int:
    return _clamp_u256(a + b)

def _sub_safe(a: int, b: int) -> int:
    return max(0, a - b)

# -----------------------------------------------------------------------------
# REGION MANAGER (off-chain helper; regions for exit nodes)
# -----------------------------------------------------------------------------

class RegionManager:
    ALLOWED_REGIONS = ("US", "EU", "AP", "SA", "AF", "OC", "ME", "XX")

    @classmethod
    def is_valid_region(cls, region: str) -> bool:
        return region is not None and len(region) <= IF_MAX_REGION_LEN and (not region or region.upper() in cls.ALLOWED_REGIONS or len(region) <= 3)

    @classmethod
    def normalize_region(cls, region: str) -> str:
        if not region:
            return "XX"
        return region.upper()[:IF_MAX_REGION_LEN]

# -----------------------------------------------------------------------------
# BANDWIDTH TRACKER (simulated bytes per tunnel/session; for limits)
# -----------------------------------------------------------------------------

class BandwidthTracker:
    def __init__(self) -> None:
        self._tunnel_bytes: Dict[str, int] = {}
        self._session_bytes: Dict[str, int] = {}
        self._lock = threading.Lock()

    def add_tunnel_bytes(self, tunnel_id: str, delta: int) -> int:
        with self._lock:
            self._tunnel_bytes[tunnel_id] = _add_safe(self._tunnel_bytes.get(tunnel_id, 0), max(0, delta))
            return self._tunnel_bytes[tunnel_id]

    def add_session_bytes(self, session_id: str, delta: int) -> int:
        with self._lock:
            self._session_bytes[session_id] = _add_safe(self._session_bytes.get(session_id, 0), max(0, delta))
            return self._session_bytes[session_id]

    def get_tunnel_bytes(self, tunnel_id: str) -> int:
        with self._lock:
            return self._tunnel_bytes.get(tunnel_id, 0)

    def get_session_bytes(self, session_id: str) -> int:
        with self._lock:
            return self._session_bytes.get(session_id, 0)

    def total_bytes(self) -> int:
        with self._lock:
            return sum(self._tunnel_bytes.values())

# -----------------------------------------------------------------------------
# KEY STORE SIMULATION (opaque key handles for tunnel encryption; no real keys)
# -----------------------------------------------------------------------------

class KeyStoreSim:
    def __init__(self) -> None:
        self._keys: Dict[str, str] = {}
        self._lock = threading.Lock()

    def put(self, handle: str, opaque: str) -> None:
        with self._lock:
            self._keys[handle] = opaque

    def get(self, handle: str) -> Optional[str]:
        with self._lock:
            return self._keys.get(handle)

    def delete(self, handle: str) -> bool:
