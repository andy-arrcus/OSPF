"""Shared pytest fixtures for OSPF tests."""

import pytest
from ipaddress import IPv4Address


@pytest.fixture
def router_id():
    return IPv4Address("10.0.0.1")


@pytest.fixture
def area_id():
    return IPv4Address("0.0.0.0")


@pytest.fixture
def neighbor_id():
    return IPv4Address("10.0.0.2")
