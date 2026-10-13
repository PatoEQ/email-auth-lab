# Escenario 1: SPF

## Objetivo

Ver qué protege **SPF** y, sobre todo, qué **no** protege. Banco Seguro publica la lista de servidores que pueden enviar su correo. La suplantación directa (A1) queda marcada como `spf=fail`, pero aun así llega. Y un atacante con un poco más de cuidado (A2) consigue un `spf=pass` en un correo que dice venir del director.

## Qué se configura

**DNS de `bancoseguro.test`:** un registro TXT nuevo en la raíz del dominio.

```
@   IN TXT  "v=spf1 ip4:172.28.0.10 -all"
```

| Parte | Significado |
|---|---|
| `v=spf1` | Esto es un registro SPF |
| `ip4:172.28.0.10` | El emisor del banco puede enviar correo de `bancoseguro.test` |
| `-all` | Cualquier otra IP: **fallo** (no autorizada) |

**Receptor:** Rspamd consulta este registro con cada correo, usando el dominio del **sobre** (`MAIL FROM`), y escribe el resultado en `Authentication-Results`. Hay un detalle propio del laboratorio: Rspamd guarda los SPF en caché un mínimo de 5 minutos. En `receptor/rspamd/spf.conf` lo ajustamos para que respete el TTL de la zona (5 s); así el cambio de escenario se nota enseguida.

**Atacante:** además de A1, ahora lanza **A2**. El atacante usa su propio dominio, `atacante.test`, que tiene su propio SPF: `v=spf1 ip4:172.28.0.66 -all`.

| | A1 · Suplantación directa | A2 · Sobre del atacante |
|---|---|---|
| MAIL FROM (sobre) | `director@bancoseguro.test` | `rebote@atacante.test` |
| From: (lo que ve el empleado) | `director@bancoseguro.test` | `director@bancoseguro.test` |
| IP de origen | 172.28.0.66 | 172.28.0.66 |

## Pasos

```bash
./lab.sh reset                  # bandeja vacía y escenario 0
./lab.sh escenario 1            # publica SPF; espera 5 s (TTL) a que caduquen las cachés
./lab.sh enviar legit           # el director real, desde 172.28.0.10
./lab.sh atacar A1              # suplantación directa
./lab.sh atacar A2              # sobre del atacante
```

En PowerShell, usa `.\lab.ps1` en lugar de `./lab.sh`.

Compara los tres correos en http://localhost:8025. En la lista, **los tres dicen venir de `director@bancoseguro.test`**. Las diferencias aparecen en *Headers*, en `Return-Path` y en `Authentication-Results`.

## Resultado esperado

| Envío | Resultado | `Authentication-Results` |
|---|---|---|
| Legítimo | Entregado | `spf=pass` (`smtp.mailfrom=director@bancoseguro.test`, IP 172.28.0.10) |
| A1 | Entregado | `spf=fail` (`smtp.mailfrom=director@bancoseguro.test`, IP 172.28.0.66) |
| A2 | Entregado | `spf=pass` (`smtp.mailfrom=rebote@atacante.test`, IP 172.28.0.66) |

Las cabeceras reales que escribe el receptor:

```
A1: spf=fail (receptor.bancoseguro.test: domain of director@bancoseguro.test does not designate
    172.28.0.66 as permitted sender) smtp.mailfrom=director@bancoseguro.test
A2: spf=pass (receptor.bancoseguro.test: domain of rebote@atacante.test designates
    172.28.0.66 as permitted sender) smtp.mailfrom=rebote@atacante.test
```

### ¿Por qué A2 obtiene `spf=pass`?

Porque SPF responde una sola pregunta: **«¿esta IP puede enviar correo del dominio que aparece en el sobre?»**

Un correo lleva dos remitentes distintos:

1. **El sobre (`MAIL FROM`, o *Return-Path*).** Se usa durante la conversación SMTP y sirve para devolver los rebotes. El empleado no lo ve.
2. **La cabecera `From:`.** Es lo que muestra el cliente de correo. El empleado solo ve esta.

En A2, el atacante pone **su** dominio en el sobre (`rebote@atacante.test`) y el del banco en el `From:`. El receptor busca el SPF de `atacante.test`, encuentra `ip4:172.28.0.66` (la IP del atacante) y concluye, con razón, que esa IP puede enviar correo de `atacante.test`. **SPF pasa.**

En ningún momento SPF compara `atacante.test` (el sobre) con `bancoseguro.test` (el `From:`). Ese control se llama **alineación**, y no lo hace SPF, sino DMARC (escenario 3).

Montar esto no le cuesta nada al atacante: basta con un dominio cualquiera con un registro SPF propio. Un `spf=pass`, por sí solo, no dice nada sobre si el `From:` es auténtico.

### ¿Y por qué A1 llega si SPF falla?

SPF le da al receptor un dato (*fail*), pero no le dice qué hacer con él. Rspamd suma unos puntos de sospecha por el `-all`, pero no los suficientes para rechazar el correo. Otros servidores reales sí rechazan los `-all`, pero no es un comportamiento estándar con el que se pueda contar. La política explícita ("si falla, rechazar") la publica el dueño del dominio con **DMARC**.

## Qué aprendimos y qué sigue sin cubrirse

- SPF autoriza **IPs** para un **dominio del sobre**. Es fácil de publicar y detecta la suplantación más burda (A1).
- **No protege el `From:` visible.** Un atacante con su propio dominio en el sobre obtiene `spf=pass` (A2).
- Un `spf=fail` sin política se queda en eso: un dato. El correo llega igual.
- Sigue sin cubrirse:
  - ninguna garantía de que el **contenido** no fue modificado (eso es DKIM, escenario 2);
  - la **alineación** entre el sobre y el `From:`, y la política de qué hacer cuando algo falla (eso es DMARC, escenario 3);
  - el **reenvío**: cuando alguien reenvía un correo, la IP cambia y SPF falla aunque el correo sea legítimo (escenario 5).

Siguiente paso: [escenario 2, DKIM](../02-dkim/README.md).

## Preguntas para la audiencia

1. Si su filtro de correo muestra `spf=pass`, ¿qué pueden afirmar sobre el remitente que ve el usuario? ¿Y qué no?
2. ¿Qué dominio aparece en el `Return-Path` de los correos que envía su organización a través de un proveedor (newsletters, facturación, CRM)?
3. ¿Por qué el banco usa `-all` y no `~all`? ¿Qué cambiaría en este laboratorio?
4. ¿Cuántos servicios externos envían correo en nombre de su dominio? ¿Están todos en su registro SPF?
