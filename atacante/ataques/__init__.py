"""Catálogo de ataques del laboratorio (CLAUDE.md, sección 5)."""

from __future__ import annotations

from collections.abc import Callable

from ataques import a1_spoof_directo, a2_sobre_atacante, a3_legitimo_alterado, a4_firma_propia
from ataques.comun import Attack, AttackResult

CATALOG: dict[str, tuple[Attack, Callable[..., AttackResult]]] = {
    "A1": (a1_spoof_directo.ATTACK, a1_spoof_directo.launch),
    "A2": (a2_sobre_atacante.ATTACK, a2_sobre_atacante.launch),
    "A3": (a3_legitimo_alterado.ATTACK, a3_legitimo_alterado.launch),
    "A4": (a4_firma_propia.ATTACK, a4_firma_propia.launch),
}
