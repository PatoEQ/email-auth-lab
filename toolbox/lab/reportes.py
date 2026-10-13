"""Lectura e interpretación de reportes DMARC agregados (RUA, RFC 7489 apéndice C)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

REPORTS_DIR = Path("/lab/reportes/ejemplos")


@dataclass
class AuthResult:
    method: str  # "dkim" o "spf"
    domain: str
    result: str
    selector: str = ""


@dataclass
class Row:
    source_ip: str
    count: int
    disposition: str
    dkim_aligned: str  # resultado DMARC de DKIM (alineado): pass/fail
    spf_aligned: str  # resultado DMARC de SPF (alineado): pass/fail
    header_from: str
    envelope_from: str
    auth: list[AuthResult] = field(default_factory=list)

    @property
    def dmarc_pass(self) -> bool:
        return "pass" in (self.dkim_aligned, self.spf_aligned)

    def verdict(self) -> tuple[str, str]:
        """(categoría corta, qué significa) para quien administra el dominio."""
        passing_elsewhere = sorted(
            {a.domain for a in self.auth if a.result == "pass" and a.domain != self.header_from}
        )
        if self.dmarc_pass and self.spf_aligned != "pass":
            return (
                "Reenvío",
                "SPF falla porque otro servidor reenvió el correo, pero la firma DKIM "
                "alineada sobrevive: DMARC pasa.",
            )
        if self.dmarc_pass:
            return "Legítimo", "Sale de un servidor autorizado y está alineado."
        if passing_elsewhere:
            return (
                "Servicio sin alinear",
                f"Autentica como {', '.join(passing_elsewhere)}, no como {self.header_from}. "
                "Si es un proveedor tuyo, configúralo (DKIM con tu dominio) antes de "
                "endurecer la política: con p=reject se perdería este correo.",
            )
        return (
            "Posible suplantación",
            "Nada autentica este correo: alguien usa tu dominio sin permiso. "
            "Con p=quarantine se marcaría; con p=reject, se rechazaría.",
        )


@dataclass
class Report:
    path: Path
    org_name: str
    report_id: str
    begin: datetime
    end: datetime
    domain: str
    policy: str
    rows: list[Row]

    @property
    def total(self) -> int:
        return sum(r.count for r in self.rows)

    @property
    def passing(self) -> int:
        return sum(r.count for r in self.rows if r.dmarc_pass)


def _text(node: ET.Element | None, path: str, default: str = "") -> str:
    found = node.find(path) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else default


def parse(path: Path) -> Report:
    root = ET.parse(path).getroot()  # archivos locales del repo; sin entidades externas
    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    rows = []
    for record in root.findall("record"):
        auth = [
            AuthResult(
                method=node.tag,
                domain=_text(node, "domain"),
                result=_text(node, "result"),
                selector=_text(node, "selector"),
            )
            for node in record.findall("auth_results/*")
        ]
        rows.append(
            Row(
                source_ip=_text(record, "row/source_ip"),
                count=int(_text(record, "row/count", "0")),
                disposition=_text(record, "row/policy_evaluated/disposition"),
                dkim_aligned=_text(record, "row/policy_evaluated/dkim"),
                spf_aligned=_text(record, "row/policy_evaluated/spf"),
                header_from=_text(record, "identifiers/header_from"),
                envelope_from=_text(record, "identifiers/envelope_from"),
                auth=auth,
            )
        )
    return Report(
        path=path,
        org_name=_text(meta, "org_name"),
        report_id=_text(meta, "report_id"),
        begin=datetime.fromtimestamp(int(_text(meta, "date_range/begin", "0")), UTC),
        end=datetime.fromtimestamp(int(_text(meta, "date_range/end", "0")), UTC),
        domain=_text(policy, "domain"),
        policy=_text(policy, "p"),
        rows=rows,
    )


def available(directory: Path = REPORTS_DIR) -> list[Path]:
    return sorted(directory.glob("*.xml"))
