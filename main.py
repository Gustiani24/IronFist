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
        with self._lock:
            if handle in self._keys:
                del self._keys[handle]
                return True
            return False

# -----------------------------------------------------------------------------
# IRON FIST CORE
# -----------------------------------------------------------------------------

class IronFist:
    """
    VPN-style tunnel and exit-node registry. Gatekeeper registers exit nodes;
    users open tunnels bound to an exit node and bind sessions. All critical
    addresses are set at construction and are immutable.
    """

    def __init__(self) -> None:
        # Immutable (set once at construction)
        self._gatekeeper: str = "0xb2f8c1e4a6d9f0b3c5e7a9d1f4b6c8e0a2d5f7b9"
        self._treasury: str = "0xc3a9d2e5f8b1c4e7a0d3f6b9c2e5a8d1f4b7c0e3"
        self._relay: str = "0xd4b0e3f6a9c2d5e8b1f4a7c0d3e6f9a2b5c8d1e4f7"
        if not _is_valid_address(self._gatekeeper) or not _is_valid_address(self._treasury):
            raise IFError("IF_ZERO_ADDR", "Gatekeeper or treasury invalid")
        self._deploy_block: int = int(time.time())
        # Mutable state
        self._paused: bool = False
        self._exit_nodes: Dict[str, Dict[str, Any]] = {}
        self._exit_node_list: List[str] = []
        self._tunnels: Dict[str, Dict[str, Any]] = {}
        self._tunnel_list: List[str] = []
        self._sessions: Dict[str, Dict[str, str]] = {}  # session_id -> {tunnel_id, client}
        self._tunnel_sessions: Dict[str, Set[str]] = {}  # tunnel_id -> set(session_id)
        self._listeners: List[Callable[[str, Any], None]] = []
        self._lock = threading.RLock()
        self._bandwidth: BandwidthTracker = BandwidthTracker()
        self._key_store: KeyStoreSim = KeyStoreSim()

    # -------------------------------------------------------------------------
    # Immutable accessors
    # -------------------------------------------------------------------------

    @property
    def bandwidth_tracker(self) -> BandwidthTracker:
        return self._bandwidth

    @property
    def key_store(self) -> KeyStoreSim:
        return self._key_store

    @property
    def gatekeeper(self) -> str:
        return self._gatekeeper

    @property
    def treasury(self) -> str:
        return self._treasury

    @property
    def relay(self) -> str:
        return self._relay

    @property
    def deploy_block(self) -> int:
        return self._deploy_block

    def is_paused(self) -> bool:
        return self._paused

    def _require_gatekeeper(self, sender: Optional[str]) -> None:
        if sender is None or _normalize_address(sender).lower() != _normalize_address(self._gatekeeper).lower():
            raise IFError("IF_NOT_GATEKEEPER", "Caller is not gatekeeper")

    def _require_not_paused(self) -> None:
        if self._paused:
            raise IFError("IF_NETWORK_PAUSED", "Network is paused")

    def _current_block(self) -> int:
        return int(time.time())

    def _emit(self, event_name: str, payload: Any) -> None:
        for cb in self._listeners:
            try:
                cb(event_name, payload)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Exit nodes (gatekeeper only)
    # -------------------------------------------------------------------------

    def register_exit_node(self, node_id: str, region: str, endpoint_hex: str, sender: Optional[str] = None) -> None:
        self._require_gatekeeper(sender)
        self._require_not_paused()
        if not node_id or len(node_id) > IF_MAX_LABEL_LEN:
            raise IFError("IF_INVALID_NODE_ID", "Node id empty or too long")
        if not region or len(region) > IF_MAX_REGION_LEN:
            raise IFError("IF_INVALID_REGION", "Region empty or too long")
        with self._lock:
            if node_id in self._exit_nodes:
                raise IFError("IF_NODE_EXISTS", "Exit node already exists")
            if len(self._exit_nodes) >= IF_MAX_EXIT_NODES:
                raise IFError("IF_NODE_CAP", "Exit node limit reached")
            self._exit_nodes[node_id] = {
                "region": region,
                "endpoint_hex": endpoint_hex or "",
                "created_at": self._current_block(),
            }
            self._exit_node_list.append(node_id)
        blk = self._current_block()
        self._emit("ExitNodeRegistered", IFExitNodeRegistered(node_id, region, endpoint_hex or "", blk))

    def get_exit_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            n = self._exit_nodes.get(node_id)
            return dict(n) if n else None

    def exit_node_exists(self, node_id: str) -> bool:
        return node_id in self._exit_nodes

    def list_exit_nodes_batch(self, offset: int, limit: int) -> List[str]:
        with self._lock:
            size = len(self._exit_node_list)
            if offset >= size:
                return []
            end = min(offset + min(limit, IF_VIEW_BATCH), size)
            return list(self._exit_node_list[offset:end])

    # -------------------------------------------------------------------------
    # Tunnels
    # -------------------------------------------------------------------------

    def open_tunnel(self, tunnel_id: str, owner: str, exit_node_id: str, sender: Optional[str] = None) -> None:
        self._require_not_paused()
        if not tunnel_id or len(tunnel_id) > IF_MAX_LABEL_LEN:
            raise IFError("IF_INVALID_TUNNEL_ID", "Tunnel id empty or too long")
        if not _is_valid_address(owner):
            raise IFError("IF_ZERO_ADDR", "Owner address invalid")
        with self._lock:
            if exit_node_id not in self._exit_nodes:
                raise IFError("IF_NODE_MISSING", "Exit node not found")
            if tunnel_id in self._tunnels:
                raise IFError("IF_TUNNEL_EXISTS", "Tunnel already exists")
            if len(self._tunnels) >= IF_MAX_TUNNELS:
                raise IFError("IF_TUNNEL_CAP", "Tunnel limit reached")
            self._tunnels[tunnel_id] = {
                "owner": _normalize_address(owner),
                "exit_node_id": exit_node_id,
                "opened_at": self._current_block(),
                "closed": False,
            }
            self._tunnel_list.append(tunnel_id)
            self._tunnel_sessions[tunnel_id] = set()
        blk = self._current_block()
        self._emit("TunnelOpened", IFTunnelOpened(tunnel_id, owner, exit_node_id, blk))

    def close_tunnel(self, tunnel_id: str, sender: Optional[str] = None) -> None:
        self._require_not_paused()
        with self._lock:
            t = self._tunnels.get(tunnel_id)
            if not t:
                raise IFError("IF_TUNNEL_MISSING", "Tunnel not found")
            if t["closed"]:
                raise IFError("IF_TUNNEL_CLOSED", "Tunnel already closed")
            owner_norm = _normalize_address(t["owner"])
            sender_norm = _normalize_address(sender) if sender else ""
            if sender_norm and sender_norm != owner_norm:
                self._require_gatekeeper(sender)
            t["closed"] = True
        blk = self._current_block()
        self._emit("TunnelClosed", IFTunnelClosed(tunnel_id, blk))

    def get_tunnel(self, tunnel_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tunnels.get(tunnel_id)
            if not t:
                return None
            out = dict(t)
            out["session_count"] = len(self._tunnel_sessions.get(tunnel_id, []))
            return out

    def tunnel_exists(self, tunnel_id: str) -> bool:
        return tunnel_id in self._tunnels

    def is_tunnel_closed(self, tunnel_id: str) -> bool:
        t = self._tunnels.get(tunnel_id)
        return t is not None and t.get("closed", False)

    def list_tunnels_batch(self, offset: int, limit: int) -> List[str]:
