# Escenario 4: límites (dominio parecido y nombre visible)

## Objetivo

Ver qué **no** resuelven SPF, DKIM y DMARC aunque estén perfectamente configurados. Banco Seguro está en `p=reject`, con SPF y DKIM alineados, y los ataques A1–A4 se rechazan. Aun así, dos ataques llegan a la bandeja **sin ninguna alerta técnica**:

- **A5, dominio parecido:** `director@bancos3guro.test`, con un "3" en lugar de la "e".
- **A6, solo el nombre visible:** `"Director General" <urgente@atacante.test>`.

## Qué se configura

**DNS de `bancoseguro.test`:** igual que en `3-reject` (SPF, DKIM `s2026` y `_dmarc` con `p=reject`). No cambia nada: el dominio ya tiene la mejor protección posible.

**Infraestructura del atacante** (publicada desde el principio del laboratorio):

| Dominio | SPF | DKIM | DMARC |
|---|---|---|---|
| `bancos3guro.test` | `v=spf1 ip4:172.28.0.66 -all` | `p2026._domainkey` | `v=DMARC1; p=reject` |
| `atacante.test` | `v=spf1 ip4:172.28.0.66 -all` | `a2026._domainkey` | (no publica) |

El dominio parecido está **mejor** configurado que muchos dominios reales: no le cuesta nada al atacante.

| | A5 · Dominio parecido | A6 · Solo el nombre visible |
|---|---|---|
| MAIL FROM (sobre) | `director@bancos3guro.test` | `urgente@atacante.test` |
| From: (lo que ve el empleado) | `director@bancos3guro.test` | `"Director General" <urgente@atacante.test>` |
| Firma DKIM | `d=bancos3guro.test`, `s=p2026` | `d=atacante.test`, `s=a2026` |

**CLI:** `lab explicar ultimo` lee de la API de Mailpit el correo más reciente. Explica en español y con colores qué revisó SPF, DKIM y DMARC, si cada uno coincide con el dominio del `From:` y qué significa el resultado. Al final da una conclusión y avisa de los engaños que estos protocolos no cubren: dominios parecidos (por sustituciones como `3`→`e` o `0`→`o`, o por diferencias de una o dos letras) y nombres visibles que no corresponden a la organización.

## Pasos

```bash
./lab.sh reset
./lab.sh escenario 4
./lab.sh enviar legit
./lab.sh atacar --todos      # A1–A4 rechazados; A5 y A6 entregados
./lab.sh atacar A5
./lab.sh explicar ultimo     # todo en verde… y la advertencia de dominio parecido
./lab.sh atacar A6
./lab.sh explicar ultimo     # nombre visible engañoso, sin DMARC
```

En PowerShell, usa `.\lab.ps1` en lugar de `./lab.sh`.

En http://localhost:8025, mira la lista de mensajes como la vería el empleado: el remitente de A6 aparece como **"Director General"**, y `bancos3guro.test` se confunde fácilmente con `bancoseguro.test` en una lectura rápida.

## Resultado esperado

| Envío | Resultado | `Authentication-Results` |
|---|---|---|
| Legítimo | Entregado | `spf=pass` · `dkim=pass` · `dmarc=pass` (bancoseguro.test) |
| A1–A4 | **Rechazados (554)** | — |
| A5 | **Entregado, sin marca** | `spf=pass` · `dkim=pass header.d=bancos3guro.test` · `dmarc=pass header.from=bancos3guro.test` |
| A6 | **Entregado, sin marca** | `spf=pass` · `dkim=pass header.d=atacante.test` · `dmarc=none` |

Un extracto de `./lab.sh explicar ultimo` después de A5:

```
PASS  DMARC — ¿respalda el dominio del From:?
   Exige que SPF o DKIM pasen para bancos3guro.test (el dominio que ves en el From:).
   Se cumple: el dominio del remitente visible respalda este correo.

Conclusión
   ⚠ Dominio parecido: bancos3guro.test imita a bancoseguro.test. SPF, DKIM y DMARC
   pueden pasar porque el correo es auténtico… de bancos3guro.test.
```

### Por qué pasan

SPF, DKIM y DMARC responden a la pregunta **«¿este correo viene de verdad del dominio que dice?»**. A5 y A6 dicen la verdad:

- **A5** viene de verdad de `bancos3guro.test`, que autoriza su IP, lo firma y publica DMARC. Todo coincide. Ningún protocolo compara `bancos3guro.test` con `bancoseguro.test`, porque para el DNS son dominios distintos sin relación alguna.
- **A6** viene de verdad de `atacante.test`. El **nombre visible** ("Director General") es texto libre: ningún protocolo lo verifica. DMARC sale `none` porque `atacante.test` no publica política, y aunque la publicara, pasaría.

La autenticación de correo protege **tu dominio exacto**, no tu **marca** ni la **atención** de las personas.

## Qué aprendimos y qué sigue sin cubrirse

- Con `p=reject`, la suplantación **exacta** del dominio (A1–A4) queda bloqueada. Es una mejora enorme y la base de todo lo demás.
- Lo que sigue sin cubrirse, y cómo se mitiga en la práctica:

| Riesgo | Mitigaciones |
|---|---|
| Dominios parecidos (A5) | Registrar las variantes más obvias del propio dominio; monitorear registros de dominios nuevos parecidos (*typosquatting*); filtros que detecten dominios "cercanos" al propio; pedir la baja de los dominios maliciosos |
| Nombre visible (A6) | Etiqueta de "remitente externo" en los correos que vienen de fuera de la organización; reglas que alerten cuando el nombre coincide con un directivo y la dirección es externa; configurar los clientes para que muestren la dirección completa |
| Ambos | **Procesos:** confirmar por otro canal (teléfono conocido, en persona) cualquier pedido de transferencia, cambio de cuenta o datos sensibles; doble aprobación de pagos; capacitación con ejemplos como estos |

- Siguiente: el [escenario 5](../05-extras/README.md) (opcional) muestra el reenvío, donde SPF falla y DKIM rescata a DMARC, y la protección de los dominios que no envían correo.

## Preguntas para la audiencia

1. Lean en voz alta, rápido: `bancoseguro.test` y `bancos3guro.test`. ¿Cuántos lo notaron?
2. En el cliente de correo de su teléfono, ¿se ve la dirección completa del remitente o solo el nombre?
3. ¿Su organización marca los correos externos? ¿Qué pasa con un correo externo cuyo nombre visible es el de su director general?
4. Si hoy llegara un pedido de transferencia urgente "del director", ¿qué proceso lo frenaría, además del filtro de correo?
