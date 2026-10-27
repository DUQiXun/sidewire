"""Find SideWire agents on the local network.

The address in ``hosts.json`` is the one thing that reliably goes stale.  A
laptop picks up a new DHCP lease, a box gets moved to another switch, someone
turns ICS on and off again, and the client sits there timing out at an address
that no longer exists.  Editing JSON by hand is not something an agent should
have to do mid-task.

So when a dial fails, the client sweeps the subnet it is already sitting on and
looks for anything listening on the agent port.  A candidate is only adopted
after a real handshake with the shared key succeeds, which means an unrelated
service on port 7900 gets ignored rather than mistaken for the target.

Stdlib only, no broadcast, no mDNS, no platform service discovery.  Just TCP
connects with a short timeout.
"""

from __future__ import annotations

import concurrent.futures as futures
import ipaddress
import socket
import time

DEFAULT_PREFIX = 24
MAX_HOSTS = 1024

# Ranges that ipaddress does not call private but that are virtual LANs in
# practice. Radmin LAN hands out 26.x, Hamachi 25.x.
VIRTUAL_LANS = ("26.0.0.0/8", "25.0.0.0/8")


def local_addresses():
    """Best-effort list of this host's IPv4 addresses.

    Two sources, because neither is reliable on its own: the resolver usually
    knows about every bound interface, while the UDP trick only reveals the one
    address the default route would use.
    """
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.append(info[4][0])
    except OSError:
        pass
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        found.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()

    out = []
    for addr in found:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        if str(ip) not in out:
            out.append(str(ip))
    return out


def subnets(addresses=None, prefix=DEFAULT_PREFIX):
    """Turn local addresses into networks worth sweeping."""
    nets = []
    for addr in addresses if addresses is not None else local_addresses():
        try:
            net = ipaddress.ip_network("%s/%d" % (addr, prefix), strict=False)
        except ValueError:
            continue
        if net not in nets:
            nets.append(net)
    return nets


def _sweep_targets(nets):
    total = 0
    for net in nets:
        for host in net.hosts():
            if total >= MAX_HOSTS:
                return
            total += 1
            yield host


def _probe_port(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        sock.connect((str(ip), port))
        return str(ip), (time.monotonic() - started) * 1000.0
    except OSError:
        return None
    finally:
        sock.close()


def scan(port, addresses=None, prefix=DEFAULT_PREFIX, timeout=0.25, workers=128):
    """Return ``[(ip, rtt_ms), ...]`` for hosts with *port* open, fastest first.

    An open port is not proof of identity -- see ``client.probe`` for that.
    """
    nets = subnets(addresses, prefix)
    targets = list(_sweep_targets(nets))
    if not targets:
        return []
    hits = []
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(lambda ip: _probe_port(ip, port, timeout), targets):
            if result:
                hits.append(result)
    hits.sort(key=lambda item: item[1])
    return hits


def is_lan_address(address):
    """True when *address* is worth sweeping for.

    RFC1918 covers the normal case. The two /8s below do not count as private
    to ``ipaddress`` because they were allocated publicly years ago, but that
    is exactly where Radmin LAN (26/8) and Hamachi (25/8) put their virtual
    adapters, and those are LANs like any other.  Loopback, link-local and
    multicast are excluded: sweeping for them either finds this machine or
    nothing.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_private:
        return True
    return any(ip in ipaddress.ip_network(net) for net in VIRTUAL_LANS)
