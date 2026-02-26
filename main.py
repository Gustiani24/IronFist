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
        with self._lock:
            size = len(self._tunnel_list)
            if offset >= size:
                return []
            end = min(offset + min(limit, IF_VIEW_BATCH), size)
            return list(self._tunnel_list[offset:end])

    # -------------------------------------------------------------------------
    # Sessions
    # -------------------------------------------------------------------------

    def bind_session(self, tunnel_id: str, session_id: str, client: str, sender: Optional[str] = None) -> None:
        self._require_not_paused()
        if not session_id or len(session_id) > IF_MAX_LABEL_LEN:
            raise IFError("IF_INVALID_SESSION_ID", "Session id empty or too long")
        if not _is_valid_address(client):
            raise IFError("IF_ZERO_ADDR", "Client address invalid")
        with self._lock:
            t = self._tunnels.get(tunnel_id)
            if not t:
                raise IFError("IF_TUNNEL_MISSING", "Tunnel not found")
            if t["closed"]:
                raise IFError("IF_TUNNEL_CLOSED", "Cannot bind to closed tunnel")
            sessions = self._tunnel_sessions.get(tunnel_id, set())
            if len(sessions) >= IF_MAX_SESSIONS_PER_TUNNEL:
                raise IFError("IF_SESSION_CAP", "Session limit per tunnel reached")
            if session_id in self._sessions:
                raise IFError("IF_SESSION_EXISTS", "Session already bound")
            self._sessions[session_id] = {"tunnel_id": tunnel_id, "client": _normalize_address(client)}
            sessions.add(session_id)
        blk = self._current_block()
        self._emit("SessionBound", IFSessionBound(tunnel_id, session_id, client, blk))

    def get_session(self, session_id: str) -> Optional[Dict[str, str]]:
        with self._lock:
            s = self._sessions.get(session_id)
            return dict(s) if s else None

    def get_tunnel_sessions(self, tunnel_id: str) -> List[str]:
        with self._lock:
            return list(self._tunnel_sessions.get(tunnel_id, []))

    # -------------------------------------------------------------------------
    # Pause / resume (gatekeeper only)
    # -------------------------------------------------------------------------

    def pause_network(self, sender: Optional[str] = None) -> None:
        self._require_gatekeeper(sender)
        self._paused = True
        blk = self._current_block()
        self._emit("NetworkPaused", IFNetworkPaused(self._gatekeeper, blk))

    def resume_network(self, sender: Optional[str] = None) -> None:
        self._require_gatekeeper(sender)
        self._paused = False
        blk = self._current_block()
        self._emit("NetworkResumed", IFNetworkResumed(self._gatekeeper, blk))

    # -------------------------------------------------------------------------
    # Event listener
    # -------------------------------------------------------------------------

    def add_listener(self, callback: Callable[[str, Any], None]) -> None:
        if callback:
            self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[str, Any], None]) -> None:
        if callback in self._listeners:
            self._listeners.remove(callback)

    # -------------------------------------------------------------------------
    # Stats / views
    # -------------------------------------------------------------------------

    def exit_node_count(self) -> int:
        return len(self._exit_nodes)

    def tunnel_count(self) -> int:
        return len(self._tunnels)

    def active_tunnel_count(self) -> int:
        return sum(1 for t in self._tunnels.values() if not t.get("closed", False))

    def session_count(self) -> int:
        return len(self._sessions)

    def run_as_gatekeeper(self, fn: Callable[[], None]) -> None:
        """Run fn with gatekeeper as effective sender (for tests)."""
        fn()

    def get_tunnels_by_owner(self, owner: str) -> List[str]:
        owner_norm = _normalize_address(owner)
        with self._lock:
            return [tid for tid, t in self._tunnels.items() if _normalize_address(t.get("owner")) == owner_norm and not t.get("closed", False)]

    def get_exit_nodes_by_region(self, region: str) -> List[str]:
        with self._lock:
            return [nid for nid, n in self._exit_nodes.items() if (n.get("region") or "").upper() == (region or "").upper()]

    def list_all_tunnel_ids(self) -> List[str]:
        with self._lock:
            return list(self._tunnel_list)

    def list_all_exit_node_ids(self) -> List[str]:
        with self._lock:
            return list(self._exit_node_list)

    def record_tunnel_bandwidth(self, tunnel_id: str, bytes_count: int) -> int:
        return self._bandwidth.add_tunnel_bytes(tunnel_id, bytes_count)

    def record_session_bandwidth(self, session_id: str, bytes_count: int) -> int:
        return self._bandwidth.add_session_bytes(session_id, bytes_count)

    def get_tunnel_bandwidth(self, tunnel_id: str) -> int:
        return self._bandwidth.get_tunnel_bytes(tunnel_id)

    def get_session_bandwidth(self, session_id: str) -> int:
        return self._bandwidth.get_session_bytes(session_id)

    def export_summary(self) -> str:
        return encode_summary(self)

# -----------------------------------------------------------------------------
# ERROR CODES (unique)
# -----------------------------------------------------------------------------

IF_ERROR_DESCRIPTIONS = {
    "IF_ZERO_ADDR": "Invalid or zero address",
    "IF_NOT_GATEKEEPER": "Caller is not gatekeeper",
    "IF_NETWORK_PAUSED": "Network is paused",
    "IF_INVALID_NODE_ID": "Exit node id empty or too long",
    "IF_INVALID_REGION": "Region empty or too long",
    "IF_NODE_EXISTS": "Exit node already exists",
    "IF_NODE_CAP": "Exit node limit reached",
    "IF_NODE_MISSING": "Exit node not found",
    "IF_INVALID_TUNNEL_ID": "Tunnel id empty or too long",
    "IF_TUNNEL_EXISTS": "Tunnel already exists",
    "IF_TUNNEL_CAP": "Tunnel limit reached",
    "IF_TUNNEL_MISSING": "Tunnel not found",
    "IF_TUNNEL_CLOSED": "Tunnel already closed",
    "IF_INVALID_SESSION_ID": "Session id empty or too long",
    "IF_SESSION_CAP": "Session limit per tunnel reached",
    "IF_SESSION_EXISTS": "Session already bound",
}

def get_error_description(code: str) -> str:
    return IF_ERROR_DESCRIPTIONS.get(code, f"Unknown: {code}")

def get_all_error_codes() -> List[str]:
    return list(IF_ERROR_DESCRIPTIONS.keys())

# -----------------------------------------------------------------------------
# HELPER: derive tunnel/session ids (deterministic)
# -----------------------------------------------------------------------------

def derive_tunnel_id(seed: str, index: int) -> str:
    h = hashlib.sha256(f"{seed}:tunnel:{index}".encode()).hexdigest()
    return f"t-{h[:16]}"

def derive_session_id(seed: str, index: int) -> str:
    h = hashlib.sha256(f"{seed}:session:{index}".encode()).hexdigest()
    return f"s-{h[:16]}"

# -----------------------------------------------------------------------------
# INTEGRITY CHECK
# -----------------------------------------------------------------------------

def run_integrity_check(net: IronFist) -> Optional[str]:
    if not _is_valid_address(net.gatekeeper):
        return "IF_ZERO_ADDR: gatekeeper"
    if not _is_valid_address(net.treasury):
        return "IF_ZERO_ADDR: treasury"
    with net._lock:
        for tid, sessions in net._tunnel_sessions.items():
            if tid not in net._tunnels:
                return "IF_TUNNEL_MISSING: orphan sessions"
            for sid in sessions:
                if sid not in net._sessions or net._sessions[sid].get("tunnel_id") != tid:
                    return "IF_SESSION_EXISTS: inconsistent session"
    return None

# -----------------------------------------------------------------------------
# STATE ENCODER (export for audit)
# -----------------------------------------------------------------------------

def encode_summary(net: IronFist) -> str:
    return (
        f"IF|{IF_VERSION}|gatekeeper={net.gatekeeper}|treasury={net.treasury}|"
        f"relay={net.relay}|deploy_block={net.deploy_block}|paused={net.is_paused()}|"
        f"exit_nodes={net.exit_node_count()}|tunnels={net.tunnel_count()}|sessions={net.session_count()}|"
        f"namespace={IF_NAMESPACE_HEX}"
    )

# -----------------------------------------------------------------------------
# RUNBOOK (procedure steps; no state change)
# -----------------------------------------------------------------------------

class IFRunbook:
    STEP_REGISTER_NODE = 1
    STEP_OPEN_TUNNEL = 2
    STEP_BIND_SESSION = 3
    STEP_CLOSE_TUNNEL = 4
    STEP_PAUSE = 5
    STEP_RESUME = 6

    @classmethod
    def describe(cls, step: int) -> str:
        if step == cls.STEP_REGISTER_NODE:
            return "Register exit node (gatekeeper only)"
        if step == cls.STEP_OPEN_TUNNEL:
            return "Open tunnel bound to exit node"
        if step == cls.STEP_BIND_SESSION:
            return "Bind session to tunnel"
        if step == cls.STEP_CLOSE_TUNNEL:
            return "Close tunnel (owner or gatekeeper)"
        if step == cls.STEP_PAUSE:
            return "Pause network (gatekeeper only)"
        if step == cls.STEP_RESUME:
            return "Resume network (gatekeeper only)"
        return "Unknown step"

    @classmethod
    def summary(cls) -> str:
        return "IronFist runbook: 1=RegisterNode 2=OpenTunnel 3=BindSession 4=CloseTunnel 5=Pause 6=Resume"

    @classmethod
    def all_steps(cls) -> List[int]:
        return [cls.STEP_REGISTER_NODE, cls.STEP_OPEN_TUNNEL, cls.STEP_BIND_SESSION, cls.STEP_CLOSE_TUNNEL, cls.STEP_PAUSE, cls.STEP_RESUME]

# -----------------------------------------------------------------------------
# GAS ESTIMATOR (off-chain approximate)
# -----------------------------------------------------------------------------

def estimate_gas_register_exit_node() -> int:
    return 95_000

def estimate_gas_open_tunnel() -> int:
    return 78_000

def estimate_gas_bind_session() -> int:
    return 65_000

def estimate_gas_close_tunnel() -> int:
    return 52_000

def estimate_gas_pause() -> int:
    return 35_000

def estimate_gas_resume() -> int:
    return 35_000

def get_all_gas_estimates() -> Dict[str, int]:
    return {
        "register_exit_node": estimate_gas_register_exit_node(),
        "open_tunnel": estimate_gas_open_tunnel(),
        "bind_session": estimate_gas_bind_session(),
        "close_tunnel": estimate_gas_close_tunnel(),
        "pause_network": estimate_gas_pause(),
        "resume_network": estimate_gas_resume(),
    }

# -----------------------------------------------------------------------------
# REPORT BUILDER (CSV / text for off-chain tools)
# -----------------------------------------------------------------------------

def build_exit_nodes_csv(net: IronFist) -> List[str]:
    lines = ["node_id,region,endpoint_hex,created_at"]
    for nid in net.list_all_exit_node_ids():
        n = net.get_exit_node(nid)
        if n:
            lines.append(f"{nid},{n.get('region','')},{n.get('endpoint_hex','')},{n.get('created_at',0)}")
    return lines

def build_tunnels_csv(net: IronFist) -> List[str]:
    lines = ["tunnel_id,owner,exit_node_id,opened_at,closed,session_count"]
    for tid in net.list_all_tunnel_ids():
        t = net.get_tunnel(tid)
        if t:
            lines.append(f"{tid},{t.get('owner','')},{t.get('exit_node_id','')},{t.get('opened_at',0)},{t.get('closed',False)},{t.get('session_count',0)}")
    return lines

def build_summary_text(net: IronFist) -> str:
    return (
        f"IronFist {IF_VERSION} | exit_nodes={net.exit_node_count()} tunnels={net.tunnel_count()} "
        f"active_tunnels={net.active_tunnel_count()} sessions={net.session_count()} paused={net.is_paused()}"
    )

# -----------------------------------------------------------------------------
# VALIDATION HELPERS (pre-flight)
# -----------------------------------------------------------------------------

def validate_register_node(net: IronFist, node_id: str, region: str) -> List[str]:
    reasons = []
    if net.is_paused():
        reasons.append("IF_NETWORK_PAUSED")
    if net.exit_node_count() >= IF_MAX_EXIT_NODES:
        reasons.append("IF_NODE_CAP")
    if not node_id or len(node_id) > IF_MAX_LABEL_LEN:
        reasons.append("IF_INVALID_NODE_ID")
    if not region or len(region) > IF_MAX_REGION_LEN:
        reasons.append("IF_INVALID_REGION")
    if net.exit_node_exists(node_id):
        reasons.append("IF_NODE_EXISTS")
    return reasons

def validate_open_tunnel(net: IronFist, tunnel_id: str, owner: str, exit_node_id: str) -> List[str]:
    reasons = []
    if net.is_paused():
        reasons.append("IF_NETWORK_PAUSED")
    if not tunnel_id or len(tunnel_id) > IF_MAX_LABEL_LEN:
        reasons.append("IF_INVALID_TUNNEL_ID")
    if not _is_valid_address(owner):
        reasons.append("IF_ZERO_ADDR")
    if not net.exit_node_exists(exit_node_id):
        reasons.append("IF_NODE_MISSING")
    if net.tunnel_exists(tunnel_id):
        reasons.append("IF_TUNNEL_EXISTS")
    if net.tunnel_count() >= IF_MAX_TUNNELS:
        reasons.append("IF_TUNNEL_CAP")
    return reasons

def validate_bind_session(net: IronFist, tunnel_id: str, session_id: str, client: str) -> List[str]:
    reasons = []
    if net.is_paused():
        reasons.append("IF_NETWORK_PAUSED")
    if not net.tunnel_exists(tunnel_id):
        reasons.append("IF_TUNNEL_MISSING")
    elif net.is_tunnel_closed(tunnel_id):
        reasons.append("IF_TUNNEL_CLOSED")
    if not session_id or len(session_id) > IF_MAX_LABEL_LEN:
        reasons.append("IF_INVALID_SESSION_ID")
    if not _is_valid_address(client):
        reasons.append("IF_ZERO_ADDR")
    if session_id and net.get_session(session_id) is not None:
        reasons.append("IF_SESSION_EXISTS")
    return reasons

def validate_close_tunnel(net: IronFist, tunnel_id: str) -> List[str]:
    reasons = []
    if net.is_paused():
        reasons.append("IF_NETWORK_PAUSED")
    if not net.tunnel_exists(tunnel_id):
        reasons.append("IF_TUNNEL_MISSING")
    elif net.is_tunnel_closed(tunnel_id):
        reasons.append("IF_TUNNEL_CLOSED")
    return reasons

# -----------------------------------------------------------------------------
# SCENARIOS (deterministic flows for testing)
# -----------------------------------------------------------------------------

def scenario_single_tunnel_single_session() -> IronFist:
    net = IronFist()
    net.run_as_gatekeeper(lambda: net.register_exit_node("node-1", "US", "0x01", net.gatekeeper))
    net.open_tunnel("t1", net.gatekeeper, "node-1")
    net.bind_session("t1", "s1", net.treasury)
    return net

def scenario_multi_region(num_nodes_per_region: int, num_tunnels: int) -> IronFist:
    net = IronFist()
    regions = ["US", "EU", "AP"]
    for r in regions:
        for i in range(num_nodes_per_region):
            nid = f"node-{r}-{i}"
            net.run_as_gatekeeper(lambda nid=nid, r=r: net.register_exit_node(nid, r, "0x00", net.gatekeeper))
    for i in range(min(num_tunnels, net.exit_node_count())):
        nids = net.list_all_exit_node_ids()
        if i < len(nids):
            net.open_tunnel(f"t-{i}", net.gatekeeper, nids[i])
    return net

def scenario_pause_resume() -> IronFist:
    net = scenario_single_tunnel_single_session()
    net.run_as_gatekeeper(lambda: net.pause_network(net.gatekeeper))
    net.run_as_gatekeeper(lambda: net.resume_network(net.gatekeeper))
    return net

# -----------------------------------------------------------------------------
