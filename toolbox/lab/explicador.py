"""Análisis de un correo entregado: SPF, DKIM, DMARC, alineación y engaños que no cubren.

Lee las cabeceras que dejó el receptor (Authentication-Results, Return-Path, Received)
y las convierte en datos que `lab explicar` presenta en español.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from lab.config import VICTIM_DOMAIN

# IPs del laboratorio, para decir de dónde vino el correo con palabras.
KNOWN_IPS = {
    "172.28.0.10": "emisor de bancoseguro.test (servidor legítimo del banco)",
    "172.28.0.40": "reenviador (lista de correo / reenvío)",
    "172.28.0.66": "atacante",
    "172.28.0.100": "toolbox del laboratorio",
}

# Sustituciones visuales típicas de los dominios parecidos.
HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"))


@dataclass
class MethodResult:
    method: str  # spf, dkim, dmarc
    result: str  # pass, fail, none, …
    comment: str = ""  # texto entre paréntesis o comillas
    props: dict[str, str] = field(default_factory=dict)


@dataclass
class Analysis:
    subject: str
    display_name: str
    from_address: str
    from_domain: str
    envelope_from: str
    source_ip: str
    spf: MethodResult
    dkim: list[MethodResult]
    dmarc: MethodResult
    quarantined: bool

    @property
    def envelope_domain(self) -> str:
        return domain_of(self.envelope_from)

    @property
    def source_label(self) -> str:
        return KNOWN_IPS.get(self.source_ip, "origen desconocido")

    @property
    def spf_aligned(self) -> bool:
        return self.spf.result == "pass" and aligned(self.envelope_domain, self.from_domain)

    def dkim_aligned(self, signature: MethodResult) -> bool:
        return signature.result == "pass" and aligned(
            signature.props.get("header.d", ""), self.from_domain
        )

    @property
    def lookalike_of(self) -> str | None:
        return lookalike_of(self.from_domain)

    @property
    def misleading_display_name(self) -> bool:
        """Nombre visible presente, con una dirección que no es del dominio de la organización."""
        return bool(self.display_name) and self.from_domain != VICTIM_DOMAIN


def domain_of(address: str) -> str:
    return parseaddr(address)[1].rpartition("@")[2].lower() or address.lower()


def organizational(domain: str) -> str:
    """Dominio organizacional simplificado (últimas dos etiquetas): basta para .test."""
    return ".".join(domain.lower().split(".")[-2:])


def aligned(domain: str, from_domain: str) -> bool:
    """Alineación relajada de DMARC: mismo dominio organizacional."""
    return bool(domain) and organizational(domain) == organizational(from_domain)


def _levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def lookalike_of(domain: str, protected: str = VICTIM_DOMAIN) -> str | None:
    """Si `domain` imita a `protected` (sin serlo), devuelve `protected`."""
    if not domain or organizational(domain) == organizational(protected):
        return None
    name, target = organizational(domain).split(".")[0], protected.split(".")[0]
    normalized = name
    for fake, real in HOMOGLYPHS:
        normalized = normalized.replace(fake, real)
    if normalized == target or _levenshtein(name, target) <= 2:
        return protected
    return None


def _split_outside(text: str, separator: str) -> list[str]:
    """Divide por `separator` ignorando lo que está entre comillas o paréntesis."""
    parts, current, depth, quoted = [], [], 0, False
    for char in text:
        if char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth = max(0, depth - 1)
        if char == separator and not quoted and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_auth_results(header: str) -> list[MethodResult]:
    """Authentication-Results (RFC 8601) → lista de resultados por método."""
    results = []
    for part in _split_outside(header, ";")[1:]:  # el primero es el servidor que verificó
        match = re.match(r"(\w+)=(\w+)", part)
        if not match:
            continue
        rest = part[match.end() :]
        comments = re.findall(r'\(([^)]*)\)|"([^"]*)"', rest)
        comment = " ".join(a or b for a, b in comments if (a or b) and "=" not in (a or b))
        props = dict(re.findall(r"([\w.]+)=\"?([^\s\";]+)\"?", rest))
        props.update(dict(re.findall(r"\((policy)=(\w+)\)", rest)))
        if "reason" in rest:
            reason = re.search(r'reason="([^"]+)"', rest)
            if reason:
                props["reason"] = reason.group(1)
        results.append(MethodResult(match.group(1), match.group(2), comment, props))
    return results


def analyze(headers: dict[str, list[str]], subject: str, quarantine_tag: str) -> Analysis:
    def first(name: str) -> str:
        values = next((v for k, v in headers.items() if k.lower() == name.lower()), [])
        return values[0] if values else ""

    display_name, from_address = parseaddr(first("From"))
    results = parse_auth_results(first("Authentication-Results"))
    by_method: dict[str, list[MethodResult]] = {}
    for result in results:
        by_method.setdefault(result.method, []).append(result)

    # La IP de origen es la que vio el receptor: su cabecera Received («… by receptor…»).
    # La primera Received suele ser el salto receptor → Mailpit, que no interesa.
    received = next(
        (r for k, v in headers.items() if k.lower() == "received" for r in v if "by receptor" in r),
        "",
    )
    ip = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", received)

    def single(method: str) -> MethodResult:
        return by_method.get(method, [MethodResult(method, "none")])[0]

    return Analysis(
        subject=subject,
        display_name=display_name,
        from_address=from_address,
        from_domain=domain_of(from_address),
        envelope_from=first("Return-Path").strip("<>"),
        source_ip=ip.group(1) if ip else "?",
        spf=single("spf"),
        dkim=by_method.get("dkim", [MethodResult("dkim", "none")]),
        dmarc=single("dmarc"),
        quarantined=subject.startswith(quarantine_tag),
    )
