"""Validación de sintaxis de los registros SPF, DKIM y DMARC publicados (`lab verificar`)."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

# Mecanismos y modificadores de SPF (RFC 7208). Los que gastan consultas DNS cuentan
# para el límite de 10.
SPF_MECHANISM = re.compile(r"^[+\-~?]?(all|ip4:\S+|ip6:\S+|a(:\S+)?|mx(:\S+)?|ptr(:\S+)?|"
                           r"include:\S+|exists:\S+)$")  # fmt: skip
SPF_MODIFIER = re.compile(r"^(redirect|exp)=\S+$")
SPF_DNS_LOOKUPS = re.compile(r"^[+\-~?]?(a|mx|ptr|include|exists)(:|$)|^redirect=")

# Tamaño de llave RSA según el largo de la llave pública DER (SubjectPublicKeyInfo).
RSA_BITS_BY_DER = ((550, 4096), (422, 3072), (294, 2048), (162, 1024))


@dataclass
class Check:
    ok: bool
    message: str
    warning: bool = False  # no es un error de sintaxis, pero conviene revisarlo


def spf(records: list[str]) -> list[Check]:
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_records:
        return [Check(False, "No hay registro SPF.")]
    if len(spf_records) > 1:
        return [Check(False, "Hay más de un registro SPF: el receptor dará permerror.")]
    terms = spf_records[0].split()[1:]
    checks = []
    invalid = [t for t in terms if not (SPF_MECHANISM.match(t) or SPF_MODIFIER.match(t))]
    checks.append(
        Check(not invalid, f"Términos inválidos: {', '.join(invalid)}")
        if invalid
        else Check(True, "Sintaxis válida (RFC 7208).")
    )
    lookups = sum(1 for t in terms if SPF_DNS_LOOKUPS.match(t))
    checks.append(Check(lookups <= 10, f"{lookups} consultas DNS adicionales (máximo 10)."))
    last = terms[-1] if terms else ""
    if last in ("-all",):
        checks.append(Check(True, "Termina en -all: las IPs no listadas fallan."))
    elif last in ("~all", "?all"):
        checks.append(Check(False, f"Termina en {last}: el resto no falla del todo.", True))
    elif not last.startswith("redirect="):
        checks.append(Check(False, "No termina en «all»: el resultado para otras IPs es neutral."))
    return checks


def _rsa_bits(der_length: int) -> int | None:
    for length, bits in RSA_BITS_BY_DER:
        if der_length >= length:
            return bits
    return None


def dkim(records: list[str]) -> list[Check]:
    if not records:
        return [Check(False, "No hay llave publicada en este selector.")]
    if len(records) > 1:
        return [Check(False, "Hay más de un TXT en el selector: la verificación es ambigua.")]
    tags = dict(
        (k.strip(), v.strip())
        for k, _, v in (t.partition("=") for t in records[0].split(";") if "=" in t)
    )
    checks = [
        Check(tags.get("v", "DKIM1") == "DKIM1", "Versión v=DKIM1."),
        Check(tags.get("k", "rsa") == "rsa", f"Tipo de llave: {tags.get('k', 'rsa')}."),
    ]
    key = re.sub(r"\s+", "", tags.get("p", ""))
    if not key:
        checks.append(Check(False, "p= vacío: la llave fue revocada."))
        return checks
    try:
        der = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        checks.append(Check(False, "p= no es base64 válido."))
        return checks
    bits = _rsa_bits(len(der))
    checks.append(
        Check(
            bits is not None and bits >= 2048,
            f"Llave RSA de {bits} bits." if bits else "Llave demasiado corta.",
        )
    )
    return checks


def dmarc(records: list[str]) -> list[Check]:
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc_records:
        bad = [r for r in records if "dmarc" in r.lower()]
        if bad:
            return [Check(False, "v=DMARC1 debe ser la primera etiqueta, exactamente así.")]
        return [Check(False, "No hay política DMARC.")]
    if len(dmarc_records) > 1:
        return [Check(False, "Hay más de un registro DMARC: el receptor lo ignorará.")]
    tags = {
        k.strip(): v.strip()
        for k, _, v in (t.partition("=") for t in dmarc_records[0].split(";") if "=" in t)
    }
    checks = []
    policy = tags.get("p")
    checks.append(
        Check(policy in ("none", "quarantine", "reject"), f"Política p={policy}.")
        if policy
        else Check(False, "Falta la etiqueta obligatoria p=.")
    )
    if "rua" in tags:
        uris = [u.strip() for u in tags["rua"].split(",")]
        bad = [u for u in uris if not re.match(r"^mailto:[^@\s]+@[^@\s]+$", u)]
        checks.append(
            Check(not bad, "Reportes rua: " + ", ".join(uris))
            if not bad
            else Check(False, f"rua inválido: {', '.join(bad)}")
        )
    else:
        checks.append(
            Check(False, "Sin rua=: no recibirás reportes de quién usa tu dominio.", True)
        )
    if "pct" in tags:
        pct_ok = tags["pct"].isdigit() and 0 <= int(tags["pct"]) <= 100
        checks.append(Check(pct_ok, f"pct={tags['pct']}."))
    for tag in ("adkim", "aspf"):
        if tag in tags:
            checks.append(Check(tags[tag] in ("r", "s"), f"{tag}={tags[tag]}."))
    return checks
