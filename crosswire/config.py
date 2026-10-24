"""Config + host registry for the CrossWire client.

Everything lives under ``$CROSSWIRE_HOME`` (default ``~/.crosswire``):

    hosts.json      host registry + defaults
    key             optional shared default key (0600)
    downloads/      where fs_pull drops files the agent can then read locally
    client.log      client-side log

Environment overrides:

    CROSSWIRE_HOME     config directory
    CROSSWIRE_HOST     default host alias
    CROSSWIRE_KEY      key for the default host (wins over hosts.json)
    CROSSWIRE_PORT     default port
"""

from __future__ import annotations

import json
import os
import stat
import sys

DEFAULT_PORT = 7900
DEFAULT_HOST_ALIAS = "sub"

_SCHEMA = {
    "default": DEFAULT_HOST_ALIAS,
    "hosts": {},
    "downloads": None,
    "limits": {
        "max_output": 200000,
        "default_timeout": 60,
        "connect_timeout": 5,
        "keepalive": 15,
    },
}


def home():
    override = os.environ.get("CROSSWIRE_HOME")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(os.path.expanduser("~"), ".crosswire")


def config_path():
    return os.path.join(home(), "hosts.json")


def ensure_home():
    h = home()
    os.makedirs(h, exist_ok=True)
    for sub in ("downloads",):
        os.makedirs(os.path.join(h, sub), exist_ok=True)
    return h


def _merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load():
    ensure_home()
    raw = {}
    path = config_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh) or {}
        except (OSError, ValueError) as exc:
            raise RuntimeError("cannot read %s: %s" % (path, exc))
    cfg = _merge(_SCHEMA, raw)
    if not cfg.get("downloads"):
        cfg["downloads"] = os.path.join(home(), "downloads")
    cfg["downloads"] = os.path.abspath(os.path.expanduser(cfg["downloads"]))
    return cfg


def save(cfg):
    ensure_home()
    path = config_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    os.replace(tmp, path)
    return path


def default_key_file():
    return os.path.join(home(), "key")


def read_key_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def write_key_file(path, key_text):
    ensure_home()
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key_text.strip() + "\n")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


class HostNotFound(Exception):
    pass


def resolve_host(cfg, alias=None):
    """Return (alias, host_dict) for *alias* (or the configured default)."""
    alias = alias or os.environ.get("CROSSWIRE_HOST") or cfg.get("default")
    hosts = cfg.get("hosts") or {}
    if not alias:
        if len(hosts) == 1:
            alias = next(iter(hosts))
        else:
            raise HostNotFound(
                "no host selected and no default configured; "
                "run `crosswire add <alias> <ip>` first")
    if alias not in hosts:
        raise HostNotFound("unknown host %r; known: %s" %
                           (alias, ", ".join(sorted(hosts)) or "(none)"))
    entry = dict(hosts[alias])
    entry.setdefault("port", int(os.environ.get("CROSSWIRE_PORT") or DEFAULT_PORT))
    entry["alias"] = alias
    return alias, entry


def host_key(entry, cfg):
    """Resolve the shared key for a host entry, in priority order."""
    key = entry.get("key")
    if key:
        return key
    env = os.environ.get("CROSSWIRE_KEY")
    if env:
        return env
    for candidate in (entry.get("key_file"), default_key_file()):
        if candidate:
            found = read_key_file(os.path.expanduser(candidate))
            if found:
                return found
    raise RuntimeError(
        "no key for host %r — set \"key\" or \"key_file\" in %s, "
        "or export CROSSWIRE_KEY" % (entry.get("alias"), config_path()))


def add_host(alias, host, port=DEFAULT_PORT, key=None, user=None, note=None,
             set_default=False, key_file=None):
    cfg = load()
    entry = {"host": host, "port": int(port or DEFAULT_PORT)}
    if key:
        entry["key"] = key.strip()
    if key_file:
        entry["key_file"] = key_file
    if user:
        entry["user"] = user
    if note:
        entry["note"] = note
    cfg.setdefault("hosts", {})[alias] = entry
    if set_default or not cfg.get("default") or cfg["default"] == DEFAULT_HOST_ALIAS and alias != DEFAULT_HOST_ALIAS and len(cfg["hosts"]) == 1:
        cfg["default"] = alias
    if not cfg.get("hosts") or len(cfg["hosts"]) == 1:
        cfg["default"] = alias
    save(cfg)
    return cfg


def remove_host(alias):
    cfg = load()
    cfg.get("hosts", {}).pop(alias, None)
    if cfg.get("default") == alias:
        cfg["default"] = next(iter(cfg.get("hosts") or {}), None)
    save(cfg)
    return cfg


def set_default(alias):
    cfg = load()
    if alias not in (cfg.get("hosts") or {}):
        raise HostNotFound("unknown host %r" % alias)
    cfg["default"] = alias
    save(cfg)
    return cfg


def platform_hint():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"
