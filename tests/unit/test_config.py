"""Tests for OSPF configuration parsing."""

import os
import tempfile
import pytest
from ipaddress import IPv4Address

from ospfd.config import OspfConfig
from ospfd.const import INTF_TYPE_BROADCAST, INTF_TYPE_P2P, AUTH_NONE, AUTH_MD5


class TestOspfConfig:
    def test_basic_config(self):
        yaml_content = """
router_id: 10.0.0.1
log_level: debug
areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: broadcast
        cost: 10
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

        assert config.router_id == IPv4Address("10.0.0.1")
        assert config.log_level == "debug"
        assert len(config.areas) == 1
        assert config.areas[0].area_id == IPv4Address("0.0.0.0")
        assert len(config.areas[0].interfaces) == 1
        assert config.areas[0].interfaces[0].name == "eth0"
        assert config.areas[0].interfaces[0].type == INTF_TYPE_BROADCAST
        assert config.areas[0].interfaces[0].cost == 10

    def test_p2p_interface(self):
        yaml_content = """
areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: point-to-point
        cost: 20
        hello_interval: 30
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

        intf = config.areas[0].interfaces[0]
        assert intf.type == INTF_TYPE_P2P
        assert intf.cost == 20
        assert intf.hello_interval == 30
        assert intf.dead_interval == 120  # 30 * 4

    def test_dead_interval_default(self):
        yaml_content = """
areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: broadcast
        hello_interval: 10
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

        assert config.areas[0].interfaces[0].dead_interval == 40

    def test_no_areas_raises(self):
        yaml_content = """
router_id: 10.0.0.1
areas: {}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            with pytest.raises(ValueError, match="At least one area"):
                OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            OspfConfig.from_yaml("/nonexistent/path.yaml")

    def test_multi_area(self):
        yaml_content = """
areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: broadcast
  0.0.0.1:
    interfaces:
      eth1:
        type: broadcast
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

        assert len(config.areas) == 2

    def test_duplicate_interface_raises(self):
        yaml_content = """
areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: broadcast
  0.0.0.1:
    interfaces:
      eth0:
        type: broadcast
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            with pytest.raises(ValueError, match="multiple areas"):
                OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

    def test_get_interface_config(self):
        yaml_content = """
areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: broadcast
        cost: 15
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = OspfConfig.from_yaml(f.name)
        os.unlink(f.name)

        intf = config.get_interface_config("eth0")
        assert intf is not None
        assert intf.cost == 15
        assert config.get_interface_config("eth999") is None
