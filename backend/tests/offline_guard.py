"""Opt-in pytest plugin: block external sockets and all DNS for the backend suite.

Run with -p offline_guard and backend/tests on PYTHONPATH. The existing proxy
tests and Windows asyncio self-pipe require numeric loopback; only that local
transport is allowed. New provider unit/service tests additionally block socket
construction altogether. No external hostnames are resolved or contacted.
"""
import ipaddress
import socket

import pytest


def pytest_sessionstart(session):
    guard = pytest.MonkeyPatch()
    session._etis_offline_guard = guard
    resolve = socket.getaddrinfo

    def numeric_host(host, family=socket.AF_UNSPEC):
        if host == 'localhost':
            return '::1' if family == socket.AF_INET6 else '127.0.0.1'
        try:
            if ipaddress.ip_address(host).is_loopback:
                return host
        except (ValueError, TypeError):
            pass
        raise AssertionError('offline suite blocked external socket or DNS')

    def resolver(host, port, family=0, type=0, proto=0, flags=0):
        return resolve(numeric_host(host, family), port, family, type, proto, flags | socket.AI_NUMERICHOST)

    def guard_address(original):
        def guarded(self, address, *args, **kwargs):
            if self.family in (socket.AF_INET, socket.AF_INET6):
                numeric_host(address[0], self.family)
            return original(self, address, *args, **kwargs)
        return guarded

    for method in ('connect', 'connect_ex', 'bind'):
        guard.setattr(socket.socket, method, guard_address(getattr(socket.socket, method)))
    original_sendto = socket.socket.sendto
    def sendto(self, data, *args):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            numeric_host(args[-1][0], self.family)
        return original_sendto(self, data, *args)
    guard.setattr(socket.socket, 'sendto', sendto)
    guard.setattr(socket, 'getaddrinfo', resolver)
    guard.setattr(socket, 'gethostbyname', numeric_host)
    guard.setattr(socket, 'gethostbyname_ex', lambda h: ('localhost', [], [numeric_host(h)]))
    guard.setattr(socket, 'gethostbyaddr', lambda h: ('localhost', [], [numeric_host(h)]))
    guard.setattr(socket, 'getfqdn', lambda h='127.0.0.1': 'localhost' if numeric_host(h) else 'localhost')


def pytest_sessionfinish(session, exitstatus):
    session._etis_offline_guard.undo()
