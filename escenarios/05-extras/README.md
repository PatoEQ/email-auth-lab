# Escenario 5 (opcional): reenvío y dominios que no envían correo

## Objetivo

Dos situaciones de producción que suelen sorprender cuando se activa DMARC:

1. **Dominios que no envían correo.** Un dominio de marca, uno antiguo o uno reservado (`noenvia.test`) también puede ser suplantado. Si no publica nada, un atacante lo usa libremente.
2. **El reenvío.** Cuando un correo legítimo se reenvía (reenvío automático de un buzón, lista de correo), sale desde otra IP y **SPF falla**. Ahí se ve por qué DKIM es imprescindible: si llega intacto, DMARC pasa igual. Pero si quien reenvía modifica el correo (como hacen muchas listas), se rompen los dos y DMARC lo rechaza.

## Qué se configura

**DNS:** lo mismo que en `3-reject` para `bancoseguro.test`, más la protección del dominio que no envía:

```
; noenvia.test (solo en el escenario 5)
@       IN TXT  "v=spf1 -all"            ; ninguna IP puede enviar correo de este dominio
_dmarc  IN TXT  "v=DMARC1; p=reject"     ; y si alguien lo intenta, rechazar
```

En producción conviene agregar también un **MX nulo** (`@ IN MX 0 .`, RFC 7505), que anuncia que el dominio tampoco recibe correo. Una opción más: `sp=reject` en el DMARC del dominio principal, para cubrir los subdominios.

**Servicio `reenviador`** (172.28.0.40, perfil `extras`): toma el último correo legítimo firmado del director y lo reenvía al empleado de dos maneras:

| Modo | Qué hace | Sobre (MAIL FROM) |
|---|---|---|
| `lab reenviar` | **Reenvío automático:** el correo viaja sin cambios, desde otra IP | el original: `director@bancoseguro.test` |
| `lab reenviar --lista` | **Lista de correo:** agrega `[Asociacion Bancaria]` al asunto, un pie al final y la cabecera `List-Id` | el de la lista: `socios-rebotes@asociacion-bancaria.test` |

**Ataque extra N1, dominio que no envía:** `facturas@noenvia.test` en el sobre y en el `From:`, sin firma. No forma parte de la tabla A1–A6, así que `--todos` no lo incluye. Se lanza con `lab atacar N1`.

## Pasos

```bash
docker compose --profile extras up -d --build   # levanta también el reenviador
./lab.sh reset

./lab.sh escenario 4
./lab.sh atacar N1            # noenvia.test no publica nada: el correo llega
./lab.sh escenario 5          # el diff muestra los registros nuevos de noenvia.test
./lab.sh atacar N1            # rechazado (554)

./lab.sh enviar legit         # un correo legítimo firmado para reenviar
./lab.sh reenviar             # reenvío tal cual
./lab.sh explicar ultimo      # SPF falla, DKIM pasa, DMARC pasa
./lab.sh reenviar --lista     # la lista modifica el correo: rechazado

./lab.sh escenario 3-none     # para ver el correo de la lista en vez de rechazarlo
./lab.sh reenviar --lista
./lab.sh explicar ultimo      # DKIM falla: el asunto y el cuerpo cambiaron
```

En PowerShell, usa `.\lab.ps1` en lugar de `./lab.sh`. El servicio `reenviador` es opcional: si no está levantado, `lab estado` lo muestra como "apagado" y `lab reenviar` explica cómo arrancarlo.

## Resultado esperado

| Envío | Escenario | Resultado | `Authentication-Results` |
|---|---|---|---|
| N1 · dominio que no envía | 4 | Entregado | `spf=none` · `dmarc=none` |
| N1 · dominio que no envía | 5 | **Rechazado (554)** | — |
| Reenvío tal cual | 5 | Entregado | `spf=fail` (IP 172.28.0.40) · `dkim=pass header.d=bancoseguro.test` · **`dmarc=pass`** |
| Lista de correo | 5 | **Rechazado (554)** | — |
| Lista de correo | 3-none | Entregado (`[Asociacion Bancaria] …`) | `dkim=fail` · `dmarc=fail` |

Los ataques A1–A6 dan lo mismo que en `3-reject`: A1–A4 rechazados, A5 y A6 entregados.

### Por qué el reenvío tal cual pasa DMARC

- **SPF falla**, porque el correo de `bancoseguro.test` llega desde 172.28.0.40, que no figura en su SPF. Así es el reenvío: SPF autoriza IPs, y el reenviador no es del banco.
- **DKIM pasa**, porque la firma viaja **dentro** del correo, y el reenviador no tocó ni las cabeceras firmadas ni el cuerpo.
- **DMARC pasa**, porque le basta con **uno** de los dos alineado: DKIM, con `d=bancoseguro.test`.

Si el banco solo tuviera SPF, este correo legítimo **se perdería** con `p=reject`. Por eso, antes de endurecer DMARC, todo el correo de la organización debe salir firmado con DKIM.

### Por qué la lista de correo es rechazada

La lista modifica el asunto y agrega un pie: cambian una cabecera firmada (`Subject`) y el cuerpo (`bh=`), así que DKIM falla. SPF tampoco salva el correo, porque el sobre es de la lista (`asociacion-bancaria.test`) y no está alineado con `bancoseguro.test`. Resultado: DMARC falla y, con `p=reject`, el correo se rechaza.

Así se resuelve en la práctica:

- Las listas modernas **reescriben el `From:`** (por ejemplo, `"Director General vía Socios" <socios@asociacion-bancaria.test>`) y firman con su propio dominio.
- O no modifican el correo.
- **ARC** (*Authenticated Received Chain*, RFC 8617) permite que un intermediario de confianza certifique "cuando lo recibí, DKIM y DMARC pasaban".

## Qué aprendimos y qué sigue sin cubrirse

- Cada dominio de la organización necesita protección, también **los que no envían correo**: `v=spf1 -all`, `p=reject` y, si corresponde, un MX nulo. Cuesta dos registros y cierra una puerta que los atacantes sí usan.
- **DKIM es lo que hace que DMARC sobreviva al reenvío.** SPF siempre se rompe al reenviar.
- Los intermediarios que **modifican** el correo (listas, pies legales agregados por un gateway, antivirus que reescriben enlaces) rompen DKIM. Hay que identificarlos en los reportes `rua` antes de pasar a `p=reject`.
- No se cubre en el laboratorio: **ARC** y **SRS** (*Sender Rewriting Scheme*). SRS reescribe el sobre al reenviar para que SPF no falle, pero no ayuda a DMARC, porque el sobre reescrito no está alineado.

## Preguntas para la audiencia

1. ¿Cuántos dominios tiene registrados su organización? ¿Cuántos envían correo? ¿Los demás publican `v=spf1 -all` y `p=reject`?
2. ¿Hay en su organización listas de correo, reenvíos automáticos o gateways que agreguen un pie a los correos salientes?
3. Si un proveedor solo puede autenticar con SPF (sin DKIM con su dominio), ¿qué pasa cuando alguien reenvía uno de sus correos?
4. ¿Por qué SRS no basta para que un correo reenviado pase DMARC?
