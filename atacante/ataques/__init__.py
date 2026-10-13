"""Catálogo de ataques del laboratorio (CLAUDE.md, sección 5)."""

from __future__ import annotations

from collections.abc import Callable

from ataques import (
    a1_spoof_directo,
    a2_sobre_atacante,
    a3_legitimo_alterado,
    a4_firma_propia,
    a5_dominio_parecido,
    a6_nombre_visible,
    n1_dominio_que_no_envia,
)
from ataques.comun import Attack, AttackResult

CATALOG: dict[str, tuple[Attack, Callable[..., AttackResult]]] = {
    "A1": (a1_spoof_directo.ATTACK, a1_spoof_directo.launch),
    "A2": (a2_sobre_atacante.ATTACK, a2_sobre_atacante.launch),
    "A3": (a3_legitimo_alterado.ATTACK, a3_legitimo_alterado.launch),
    "A4": (a4_firma_propia.ATTACK, a4_firma_propia.launch),
    "A5": (a5_dominio_parecido.ATTACK, a5_dominio_parecido.launch),
    "A6": (a6_nombre_visible.ATTACK, a6_nombre_visible.launch),
    # Extra del escenario 5 (fuera de la tabla de verdad y de --todos).
    "N1": (n1_dominio_que_no_envia.ATTACK, n1_dominio_que_no_envia.launch),
}
