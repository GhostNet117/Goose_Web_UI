"""Built-in HTTPS (spec 015): Goose Web's own local certificate authority and server certificate.

Modes (`server.tls`, or Admin > System > HTTPS, which wins when set):

- ``auto`` (default): ``self-signed`` unless ``server.public_url`` is set (then a reverse proxy in front of the
  gateway terminates TLS, so ``off``).
- ``self-signed``: Goose Web creates a local CA (10 years) and a server certificate signed by it (90 days) for every
  name and address of this machine: localhost, 127.0.0.1, ::1, the host name and FQDN, the machine's IP addresses,
  the bind address, the public_url host, ``server.allowed_hosts`` and ``server.tls_names``. The server certificate
  is renewed automatically 30 days before it expires and whenever the set of names/addresses changes; the running
  gateway loads the new certificate without a restart. Browsers trust it once the CA (``/tls/ca.crt``) is imported
  (``goose-web tls trust`` on Windows, or the browser/OS certificate settings).
- ``files``: use an existing certificate and key (PEM), for example from a company CA: ``server.tls_cert_file`` and
  ``server.tls_key_file``.
- ``off``: plain HTTP (behind a reverse proxy that terminates TLS, such as Caddy or nginx).

Switching modes takes effect when the gateway restarts. Files live in ``<system_dir>/tls/`` (``ca.key`` never leaves
it). ``ca.key`` and ``server.key`` are readable only by the gateway's account and SYSTEM (Windows: inheritance
removed; POSIX: mode 600).

The CA carries a critical NameConstraints extension: it can only sign for the names the server certificate covers
(localhost, the host name and FQDN, the public_url host, allowed_hosts, tls_names, and their subdomains) and for
loopback and private/shared addresses (127/8, ::1, 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) plus any
public address the certificate itself needs. A stolen ``ca.key`` therefore cannot impersonate other sites to the
clients that trust the CA. A CA without constraints (Goose Web 1.11) or one whose constraints do not cover a name
that is needed now is replaced by a new CA (logged as a warning: clients must import the new ``ca.crt``).
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import os
import socket
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("goose_web.tls")

MODES = ("auto", "self-signed", "files", "off")
CA_DAYS = 3650
LEAF_DAYS = 90
RENEW_DAYS = 30
SETTING_KEY = "tls"            # Admin UI override in the settings table: {"mode", "certFile", "keyFile"}

# The live server's SSL context (set by `goose-web serve`); renewals load the new certificate into it.
ACTIVE: dict[str, Any] = {"context": None, "mode": "off", "cert": "", "key": ""}


def is_active() -> bool:
    return ACTIVE.get("context") is not None


# ------------------------------------------------------------------ configuration
def configured(settings, override: dict | None = None) -> dict:
    """The TLS configuration: config.yaml/env, overridden by the Admin UI setting when present."""
    mode = str(settings.get("server", "tls") or "auto").strip().lower()
    cert = str(settings.get("server", "tls_cert_file") or "")
    key = str(settings.get("server", "tls_key_file") or "")
    source = "config"
    if isinstance(override, dict) and override.get("mode"):
        mode = str(override["mode"]).strip().lower()
        cert = str(override.get("certFile") or cert)
        key = str(override.get("keyFile") or key)
        source = "admin"
    if mode in ("false", "no", "0", "none", "disabled"):
        mode = "off"
    if mode in ("true", "yes", "on", "1", "selfsigned", "self_signed"):
        mode = "self-signed"
    if mode not in MODES:
        raise ValueError(f"server.tls must be one of {', '.join(MODES)} (got {mode!r})")
    effective = mode
    if mode == "auto":
        effective = "off" if str(settings.public_url or "") else "self-signed"
    return {"mode": mode, "effective": effective, "certFile": cert, "keyFile": key, "source": source}


def tls_dir(settings) -> Path:
    return Path(settings.system_dir) / "tls"


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def local_names(settings) -> tuple[list[str], list[str]]:
    """(DNS names, IP addresses) the server certificate must cover."""
    dns: set[str] = {"localhost"}
    ips: set[str] = {"127.0.0.1", "::1"}

    def add(v: Any) -> None:
        v = str(v or "").strip().strip("[]").rstrip(".").lower()
        if not v or v in ("0.0.0.0", "::", "*"):  # nosec B104 - detects a wildcard bind, never binds
            return
        if _is_ip(v):
            ip = ipaddress.ip_address(v)
            if not ip.is_link_local and not ip.is_unspecified and not ip.is_multicast:
                ips.add(str(ip))
        elif all(ch.isalnum() or ch in "-." for ch in v):
            dns.add(v)
    host = socket.gethostname()
    add(host)
    try:
        add(socket.getfqdn())
    except OSError:
        pass
    for name in {host, "localhost"}:
        try:
            for info in socket.getaddrinfo(name, None):
                add(info[4][0].split("%")[0])
        except OSError:
            pass
    add(settings.get("server", "host"))
    if settings.public_url:
        try:
            add(urlsplit(settings.public_url).hostname)
        except ValueError:
            pass
    extra = []
    for key in ("allowed_hosts", "tls_names"):
        v = settings.get("server", key) or []
        extra += v.split(",") if isinstance(v, str) else list(v)
    for v in extra:
        add(v)
    return sorted(dns), sorted(ips, key=lambda s: (":" in s, s))


# ------------------------------------------------------------------ certificate files
def _x509():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


def restrict_to_owner(path: Path) -> None:
    """Owner-only access to a key file: Windows - inheritance removed, Full control for the current user and
    SYSTEM only (icacls /inheritance:r /grant:r); POSIX - mode 600. Raises OSError if that fails."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    import subprocess
    from . import winsec
    sid = winsec.current_user_sid()
    if not sid:
        raise OSError(f"cannot restrict {path}: current user SID unknown")
    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    r = subprocess.run([icacls, str(path), "/inheritance:r", "/grant:r", f"*{sid}:F", "*S-1-5-18:F", "/Q"],  # nosec B603
                       capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, creationflags=0x08000000)
    if r.returncode != 0:
        raise OSError(f"icacls {path} failed: {(r.stdout + r.stderr).strip()[:300]}")


def _write_file(path: Path, data: bytes, private: bool = True) -> None:
    """Write via a temporary file and replace. A private file (key) is restricted to its owner BEFORE the key
    bytes are written into it, and keeps that ACL when it replaces the old file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    if private:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        os.close(fd)
        try:
            restrict_to_owner(tmp)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        with open(tmp, "r+b") as fh:
            fh.write(data)
    else:
        tmp.write_bytes(data)
    os.replace(tmp, path)


def _write_private(path: Path, data: bytes) -> None:
    _write_file(path, data, private=True)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# Addresses the CA may sign for besides the machine's own names: loopback and the private/shared ranges a LAN or
# VPN uses. A public address is only permitted when this machine's certificate needs it (then as a single address).
PRIVATE_NETS = ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                "fc00::/7")


def _constraints_for(dns: list[str], ips: list[str]) -> tuple[list[str], list[str]]:
    """(permitted DNS names, permitted networks) of the CA's NameConstraints for these certificate names."""
    nets = [ipaddress.ip_network(n) for n in PRIVATE_NETS]
    extra = []
    for i in ips:
        a = ipaddress.ip_address(i)
        if not any(a.version == n.version and a in n for n in nets):
            extra.append(ipaddress.ip_network(f"{a}/{a.max_prefixlen}"))
    return sorted(set(dns)), [str(n) for n in nets + extra]


def ca_constraints(cert) -> tuple[list[str], list[str]] | None:
    """(permitted DNS names, permitted networks) of a CA certificate, or None if it has no NameConstraints."""
    from cryptography import x509
    try:
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None
    subtrees = nc.permitted_subtrees or []
    return ([s.value for s in subtrees if isinstance(s, x509.DNSName)],
            [str(s.value) for s in subtrees if isinstance(s, x509.IPAddress)])


def _outside(constraints: tuple[list[str], list[str]], dns: list[str], ips: list[str]) -> list[str]:
    """The names/addresses a CA with these constraints could not sign for (RFC 5280 DNS subtree matching)."""
    pdns, pnets = constraints
    nets = [ipaddress.ip_network(n) for n in pnets]
    out = []
    for n in dns:
        n = n.lower().rstrip(".")
        if not any(n == b.lower() or n.endswith("." + b.lower().lstrip(".")) for b in pdns):
            out.append(n)
    for i in ips:
        a = ipaddress.ip_address(i)
        if not any(a.version == net.version and a in net for net in nets):
            out.append(i)
    return out


def _ensure_ca(d: Path, dns: list[str] | None = None, ips: list[str] | None = None):
    """The local CA: reused while it is valid long enough, carries NameConstraints and permits every name in
    dns/ips; otherwise a new one is created (clients must import the new ca.crt). Returns (key, cert, created,
    why)."""
    x509, hashes, serialization, ec, _, NameOID = _x509()
    dns, ips = list(dns or ["localhost"]), list(ips or ["127.0.0.1", "::1"])
    kp, cp = d / "ca.key", d / "ca.crt"
    why = "no CA yet"
    if kp.exists() and cp.exists():
        key = serialization.load_pem_private_key(kp.read_bytes(), None)
        cert = x509.load_pem_x509_certificate(cp.read_bytes())
        cons = ca_constraints(cert)
        missing = _outside(cons, dns, ips) if cons else []
        if cert.not_valid_after_utc - _now() <= dt.timedelta(days=LEAF_DAYS + RENEW_DAYS):
            why = "the CA expires soon"
        elif cons is None:
            why = "the CA has no name constraints (created by Goose Web 1.11 or earlier)"
        elif missing:
            why = "names outside the CA's constraints: " + ", ".join(missing)
        else:
            return key, cert, False, ""
        log.warning("creating a new local CA (%s). Every client that trusted the old CA must import the new ca.crt "
                    "(/tls/ca.crt or goose-web tls trust)", why)
    pdns, pnets = _constraints_for(dns, ips)
    key = ec.generate_private_key(ec.SECP256R1())
    # the creation date tells a replaced CA from its successor in a certificate store
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         f"Goose Web local CA {_now():%Y-%m-%d} ({socket.gethostname()})"[:64]),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Goose Web")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5)).not_valid_after(_now() + dt.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ski, critical=False)
            # A-6: even with a stolen key this CA can only sign for this machine's names and private addresses
            .add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(n) for n in pdns]
                + [x509.IPAddress(ipaddress.ip_network(n)) for n in pnets], excluded_subtrees=None), critical=True)
            .sign(key, hashes.SHA256()))
    _write_private(kp, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    _write_file(cp, cert.public_bytes(serialization.Encoding.PEM), private=False)
    log.info("created local CA %s (valid until %s), limited to %s and %s", cert.subject.rfc4514_string(),
             cert.not_valid_after_utc.date(), ", ".join(pdns), ", ".join(pnets))
    return key, cert, True, why


def _leaf_names(cert) -> tuple[list[str], list[str]]:
    from cryptography import x509
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    return (sorted(san.get_values_for_type(x509.DNSName)),
            sorted((str(i) for i in san.get_values_for_type(x509.IPAddress)), key=lambda s: (":" in s, s)))


def ensure(settings, force: bool = False) -> dict:
    """Create or renew the self-signed certificate if needed. Returns status() plus 'renewed' (bool) and 'reason'."""
    x509, hashes, serialization, ec, EKU, NameOID = _x509()
    d = tls_dir(settings)
    d.mkdir(parents=True, exist_ok=True)
    dns, ips = local_names(settings)
    ca_key, ca_cert, ca_new, ca_why = _ensure_ca(d, dns, ips)
    kp, cp = d / "server.key", d / "server.crt"
    reason = "forced" if force else ""
    if not reason and ca_new:
        reason = "new CA" + (f" ({ca_why})" if ca_why and ca_why != "no CA yet" else "")
    if not reason and not (kp.exists() and cp.exists()):
        reason = "no certificate yet"
    if not reason:
        cur = x509.load_pem_x509_certificate(cp.read_bytes())
        left = cur.not_valid_after_utc - _now()
        have_dns, have_ips = _leaf_names(cur)
        if left < dt.timedelta(days=RENEW_DAYS):
            reason = f"expires in {max(0, left.days)} days"
        elif set(dns) - set(have_dns) or set(ips) - set(have_ips):
            reason = "new names/addresses: " + ", ".join(sorted((set(dns) - set(have_dns)) | (set(ips) - set(have_ips))))
        elif cur.issuer != ca_cert.subject:
            reason = "issued by another CA"
    if not reason:
        return dict(status(settings), cert=describe_cert(cp), renewed=False, reason="")
    key = ec.generate_private_key(ec.SECP256R1())
    host = socket.gethostname()
    san = [x509.DNSName(n) for n in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (host or "localhost")[:64]),
                                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Goose Web")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5)).not_valid_after(_now() + dt.timedelta(days=LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([EKU.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write_private(kp, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    # Chain file: server certificate + CA, so clients that are given the CA can verify it.
    _write_file(cp, cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM),
                private=False)
    (d / "state.json").write_text(json.dumps({"renewedAt": _now().isoformat(), "reason": reason}), encoding="utf-8")
    log.info("server certificate %s (%s): %d names, valid until %s", "renewed" if not ca_new else "created", reason,
             len(san), cert.not_valid_after_utc.date())
    return dict(status(settings), cert=describe_cert(cp), renewed=True, reason=reason)


def _fingerprint(cert) -> str:
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def describe_cert(path: str | Path) -> dict:
    """Subject, issuer, validity, names and SHA-256 fingerprint of the first certificate in a PEM file."""
    from cryptography import x509
    try:
        cert = x509.load_pem_x509_certificates(Path(path).read_bytes())[0]
    except (OSError, ValueError, IndexError) as e:
        return {"error": str(e)}
    dns, ips = _leaf_names(cert)
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "notBefore": cert.not_valid_before_utc.isoformat(), "notAfter": cert.not_valid_after_utc.isoformat(),
            "daysLeft": (cert.not_valid_after_utc - _now()).days, "dns": dns, "ips": ips,
            "sha256": _fingerprint(cert)}


def status(settings, override: dict | None = None) -> dict:
    try:
        cfg = configured(settings, override)
    except ValueError as e:
        cfg = {"mode": "?", "effective": "off", "error": str(e)}
    d = tls_dir(settings)
    out: dict[str, Any] = dict(cfg, active=is_active(), activeMode=ACTIVE.get("mode") if is_active() else "off",
                               dir=str(d))
    if (d / "ca.crt").exists():
        out["ca"] = describe_cert(d / "ca.crt")
    if cfg.get("effective") == "self-signed" and (d / "server.crt").exists():
        out["cert"] = describe_cert(d / "server.crt")
    elif cfg.get("effective") == "files" and cfg.get("certFile"):
        out["cert"] = describe_cert(cfg["certFile"])
    dns, ips = local_names(settings)
    out["wantedNames"] = dns + ips
    return out


def server_files(settings, override: dict | None = None) -> tuple[str, str, str]:
    """(mode, certfile, keyfile) for `goose-web serve`; ('off', '', '') for plain HTTP."""
    cfg = configured(settings, override)
    mode = cfg["effective"]
    if mode == "self-signed":
        ensure(settings)
        d = tls_dir(settings)
        return mode, str(d / "server.crt"), str(d / "server.key")
    if mode == "files":
        cert, key = cfg["certFile"], cfg["keyFile"]
        if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
            raise ValueError("server.tls is 'files' but tls_cert_file / tls_key_file are missing or not readable")
        return mode, cert, key
    return "off", "", ""


def activate(context: ssl.SSLContext | None, mode: str, cert: str, key: str) -> None:
    ACTIVE.update(context=context, mode=mode if context is not None else "off", cert=cert, key=key)


def reload_active() -> bool:
    """Load the (renewed) certificate files into the running server's SSL context; new connections use them."""
    ctx = ACTIVE.get("context")
    if ctx is None:
        return False
    ctx.load_cert_chain(ACTIVE["cert"], ACTIVE["key"])
    return True
