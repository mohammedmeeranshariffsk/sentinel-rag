import socket

import pytest


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """The normal suite must never contact Gemini or other network services."""
    def fail(*args, **kwargs):
        raise AssertionError("Network access is disabled in unit tests")

    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket.socket, "connect_ex", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
