"""OSPF daemon configuration (YAML-based).

Parses and validates the ospfd.yaml configuration file into
typed dataclass structures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from typing import Optional

import yaml

from ospfd.const import (
    AUTH_MD5,
    AUTH_NONE,
    AUTH_SIMPLE,
    DEFAULT_COST,
    DEFAULT_DEAD_INTERVAL_MULTIPLIER,
    DEFAULT_HELLO_INTERVAL_BROADCAST,
    DEFAULT_INF_TRANS_DELAY,
    DEFAULT_PRIORITY,
    DEFAULT_RXMT_INTERVAL,
    INTF_TYPE_BROADCAST,
    INTF_TYPE_NBMA,
    INTF_TYPE_P2MP,
    INTF_TYPE_P2P,
    INTF_TYPE_VIRTUAL,
    LS_REFRESH_TIME,
)

logger = logging.getLogger(__name__)

_INTF_TYPE_MAP = {
    "broadcast": INTF_TYPE_BROADCAST,
    "point-to-point": INTF_TYPE_P2P,
    "p2p": INTF_TYPE_P2P,
    "nbma": INTF_TYPE_NBMA,
    "point-to-multipoint": INTF_TYPE_P2MP,
    "p2mp": INTF_TYPE_P2MP,
    "virtual": INTF_TYPE_VIRTUAL,
}

_AUTH_TYPE_MAP = {
    "none": AUTH_NONE,
    "simple": AUTH_SIMPLE,
    "md5": AUTH_MD5,
}


@dataclass
class AuthConfig:
    """Authentication configuration for an interface."""

    type: int = AUTH_NONE
    key: bytes = b""
    key_id: int = 0


@dataclass
class InterfaceConfig:
    """Configuration for a single OSPF interface."""

    name: str
    type: int = INTF_TYPE_BROADCAST
    cost: int = DEFAULT_COST
    priority: int = DEFAULT_PRIORITY
    hello_interval: int = DEFAULT_HELLO_INTERVAL_BROADCAST
    dead_interval: int = 0  # 0 means auto (hello * 4)
    retransmit_interval: int = DEFAULT_RXMT_INTERVAL
    transmit_delay: int = DEFAULT_INF_TRANS_DELAY
    passive: bool = False
    auth: AuthConfig = field(default_factory=AuthConfig)

    def __post_init__(self) -> None:
        if self.dead_interval == 0:
            self.dead_interval = self.hello_interval * DEFAULT_DEAD_INTERVAL_MULTIPLIER


@dataclass
class AreaConfig:
    """Configuration for a single OSPF area."""

    area_id: IPv4Address
    stub: bool = False
    default_cost: int = 1
    interfaces: list[InterfaceConfig] = field(default_factory=list)


@dataclass
class RedistributeConfig:
    """Route redistribution configuration."""

    static: bool = False
    connected: bool = False
    metric: int = 20
    metric_type: int = 2  # E1 or E2


@dataclass
class OspfConfig:
    """Top-level OSPF daemon configuration."""

    router_id: Optional[IPv4Address] = None
    log_level: str = "info"
    log_file: Optional[str] = None
    pid_file: str = "/var/run/ospfd.pid"
    spf_delay: float = 1.0
    spf_hold: float = 5.0
    lsa_refresh: int = LS_REFRESH_TIME
    areas: list[AreaConfig] = field(default_factory=list)
    redistribute: RedistributeConfig = field(default_factory=RedistributeConfig)

    @classmethod
    def from_yaml(cls, path: str) -> OspfConfig:
        """Load and validate configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            A validated OspfConfig instance.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
            ValueError: If the config is invalid.
        """
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(config_path) as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ValueError("Config file must contain a YAML mapping")

        return cls._parse(raw)

    @classmethod
    def _parse(cls, raw: dict) -> OspfConfig:
        """Parse a raw config dict into an OspfConfig."""
        config = cls()

        # Router ID
        rid = raw.get("router_id")
        if rid:
            config.router_id = IPv4Address(rid)

        # Logging
        config.log_level = raw.get("log_level", "info")
        config.log_file = raw.get("log_file")
        config.pid_file = raw.get("pid_file", "/var/run/ospfd.pid")

        # Timers
        timers = raw.get("timers", {})
        if isinstance(timers, dict):
            config.spf_delay = float(timers.get("spf_delay", 1.0))
            config.spf_hold = float(timers.get("spf_hold", 5.0))
            config.lsa_refresh = int(timers.get("lsa_refresh", LS_REFRESH_TIME))

        # Areas
        areas_raw = raw.get("areas", {})
        if isinstance(areas_raw, dict):
            for area_id_str, area_data in areas_raw.items():
                area_config = cls._parse_area(area_id_str, area_data or {})
                config.areas.append(area_config)

        # Redistribution
        redist_raw = raw.get("redistribute", {})
        if isinstance(redist_raw, dict):
            config.redistribute = RedistributeConfig(
                static=redist_raw.get("static", False),
                connected=redist_raw.get("connected", False),
                metric=redist_raw.get("metric", 20),
                metric_type=redist_raw.get("metric_type", 2),
            )

        config._validate()
        return config

    @classmethod
    def _parse_area(cls, area_id_str: str, data: dict) -> AreaConfig:
        """Parse a single area config."""
        area = AreaConfig(
            area_id=IPv4Address(area_id_str),
            stub=data.get("stub", False),
            default_cost=data.get("default_cost", 1),
        )

        interfaces_raw = data.get("interfaces", {})
        if isinstance(interfaces_raw, dict):
            for intf_name, intf_data in interfaces_raw.items():
                intf_config = cls._parse_interface(intf_name, intf_data or {})
                area.interfaces.append(intf_config)

        return area

    @classmethod
    def _parse_interface(cls, name: str, data: dict) -> InterfaceConfig:
        """Parse a single interface config."""
        intf_type_str = data.get("type", "broadcast").lower()
        intf_type = _INTF_TYPE_MAP.get(intf_type_str)
        if intf_type is None:
            raise ValueError(f"Unknown interface type '{intf_type_str}' for {name}")

        auth_config = AuthConfig()
        auth_raw = data.get("auth", {})
        if isinstance(auth_raw, dict):
            auth_type_str = auth_raw.get("type", "none").lower()
            auth_type = _AUTH_TYPE_MAP.get(auth_type_str)
            if auth_type is None:
                raise ValueError(f"Unknown auth type '{auth_type_str}' for {name}")
            auth_config.type = auth_type
            key = auth_raw.get("key", "")
            if isinstance(key, str):
                auth_config.key = key.encode()
            md5_raw = auth_raw.get("md5", {})
            if isinstance(md5_raw, dict):
                auth_config.key_id = md5_raw.get("key_id", 0)
                md5_key = md5_raw.get("key", "")
                if isinstance(md5_key, str):
                    auth_config.key = md5_key.encode()

        return InterfaceConfig(
            name=name,
            type=intf_type,
            cost=data.get("cost", DEFAULT_COST),
            priority=data.get("priority", DEFAULT_PRIORITY),
            hello_interval=data.get("hello_interval", DEFAULT_HELLO_INTERVAL_BROADCAST),
            dead_interval=data.get("dead_interval", 0),
            retransmit_interval=data.get("retransmit_interval", DEFAULT_RXMT_INTERVAL),
            transmit_delay=data.get("transmit_delay", DEFAULT_INF_TRANS_DELAY),
            passive=data.get("passive", False),
            auth=auth_config,
        )

    def _validate(self) -> None:
        """Validate the parsed configuration."""
        if not self.areas:
            raise ValueError("At least one area must be configured")

        seen_interfaces: set[str] = set()
        for area in self.areas:
            if not area.interfaces:
                raise ValueError(f"Area {area.area_id} has no interfaces")
            for intf in area.interfaces:
                if intf.name in seen_interfaces:
                    raise ValueError(f"Interface {intf.name} configured in multiple areas")
                seen_interfaces.add(intf.name)
                if intf.hello_interval <= 0:
                    raise ValueError(f"Interface {intf.name}: hello_interval must be > 0")
                if intf.dead_interval <= 0:
                    raise ValueError(f"Interface {intf.name}: dead_interval must be > 0")
                if intf.cost <= 0:
                    raise ValueError(f"Interface {intf.name}: cost must be > 0")

    def get_interface_area(self, intf_name: str) -> Optional[AreaConfig]:
        """Find which area an interface belongs to."""
        for area in self.areas:
            for intf in area.interfaces:
                if intf.name == intf_name:
                    return area
        return None

    def get_interface_config(self, intf_name: str) -> Optional[InterfaceConfig]:
        """Get the configuration for a specific interface."""
        for area in self.areas:
            for intf in area.interfaces:
                if intf.name == intf_name:
                    return intf
        return None
