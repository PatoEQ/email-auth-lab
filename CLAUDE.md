# CLAUDE.md — email-auth-lab

Contexto e instrucciones para Claude Code. Léelo completo antes de cada fase.

## 1. Qué es este proyecto

Laboratorio educativo, 100 % local, que demuestra **SPF, DKIM y DMARC**: qué son, cómo se implementan y de qué protegen. Se usa en una presentación en vivo y se publica en GitHub para que cualquiera lo replique.

**Historia conductora (fraude del CEO / BEC):** la empresa ficticia *Banco Seguro* (`bancoseguro.test`). Un atacante envía a `empleado@bancoseguro.test` un correo que dice venir de `director@bancoseguro.test` pidiendo una transferencia urgente. Cada escenario repite los mismos ataques con una defensa más.

**Público:** personas de TI y seguridad, no necesariamente expertas en correo. Todo texto que vea el usuario va en **español**, claro y sin jerga innecesaria.

## 2. Reglas no negociables

1. **Solo dominios `.test`** (RFC 2606): `bancoseguro.test`, `atacante.test`, `bancos3guro.test`, `noenvia.test`. Nunca un dominio real.
2. **Red aislada:** `lab-net` es `internal: true`. Ningún contenedor que envíe correo tiene salida a Internet.
3. **Los scripts de ataque validan el destino:** solo aceptan dominios `.test` y el host `receptor`. Cualquier otro destino aborta con un mensaje claro en español.
4. **Ningún secreto en el repo.** Las llaves DKIM se generan al arrancar, viven en un volumen y su ruta está en `.gitignore`. Nada de llaves "de ejemplo".
5. **Sin socket de Docker dentro de los contenedores.** El cambio de escenario no puede depender de montar `/var/run/docker.sock`.
6. **Puertos al host solo en `127.0.0.1`**, nunca en `0.0.0.0`. Solo se expone la interfaz de Mailpit (8025).
7. **Finales de línea LF** en todo el repo (`.gitattributes` con `* text=auto eol=lf`). Los scripts deben funcionar si el repo se clona en Windows.
8. **No des una fase por terminada** sin haber levantado el entorno y corrido los tests de esa fase. Si algo no se puede verificar, dilo explícitamente.

## 3. Arquitectura

| Servicio | IP en `lab-net` | Imagen / base | Función |
|---|---|---|---|
| `init` | — (one-shot) | Debian + opendkim-tools | Genera llaves DKIM si faltan y renderiza las zonas DNS con las llaves públicas |
| `dns` | 172.28.0.53 | `coredns/coredns` | Sirve las zonas `.test`; recarga sola cuando cambian los archivos |
| `emisor` | 172.28.0.10 | Debian + Postfix + OpenDKIM | Servidor de salida legítimo de `bancoseguro.test` |
| `receptor` | 172.28.0.25 | Debian + Postfix + Rspamd (milter) | MX de `bancoseguro.test`; verifica SPF/DKIM/DMARC y aplica la política |
| `mailpit` | 172.28.0.30 | `axllent/mailpit` | Bandeja web; recibe del receptor lo que se entrega |
| `atacante` | 172.28.0.66 | Debian + swaks + Python | Lanza los ataques A1–A6 |
| `toolbox` | 172.28.0.100 | Python 3.12 + dnsutils | CLI `lab`, explicador, reportes, tests |
| `reenviador` | 172.28.0.40 | Debian + swaks | Solo escenario 5 (perfil `extras`) |

- Subred `172.28.0.0/24`. Todos los contenedores usan `dns` (172.28.0.53) como resolvedor.
- Flujo legítimo: `emisor` → `receptor` (MX) → `mailpit`.
- Flujo de ataque: `atacante` → `receptor` → `mailpit` o rechazo SMTP.

### Detalles técnicos que debes respetar (verifícalos, no los asumas)

- **Puerto de Mailpit:** Docker no publica puertos de contenedores que solo están en una red `internal`. Mailpit va en dos redes: `lab-net` y `ui-net` (bridge normal), y publica `127.0.0.1:8025:8025`. Nadie más está en `ui-net`.
- **Rspamd y redes privadas:** Rspamd trata los rangos privados como locales (`local_addrs`) y puede saltarse verificaciones. Ajusta la configuración para que verifique SPF, DKIM y DMARC del tráfico de `172.28.0.0/24`. Comprueba que la cabecera `Authentication-Results` aparezca con resultados reales.
- **Postfix del receptor:** `mynetworks` solo localhost. Acepta correo únicamente para `bancoseguro.test` y lo reenvía a `mailpit:1025`.
- **Política DMARC:** el receptor debe aplicar `quarantine` (marca de spam visible en Mailpit) y `reject` (respuesta SMTP 5xx). Confirma la sintaxis vigente del módulo DMARC de Rspamd en su documentación oficial.
- **TTL bajos** (5 s) en todas las zonas para que los cambios de escenario se vean al instante. Incrementa el serial SOA en cada cambio.
- **Cambio de escenario sin docker.sock:** la toolbox escribe el escenario activo en el volumen compartido `estado/`. CoreDNS lo recoge con su recarga automática. El emisor activa o desactiva la firma DKIM según ese estado. Si OpenDKIM no recarga en caliente de forma fiable, el wrapper del host (`lab.sh` / `lab.ps1`) reinicia solo el servicio `emisor`.

## 4. Registros DNS por escenario

Selectores DKIM: `s2026` (bancoseguro), `a2026` (atacante), `p2026` (bancos3guro). Llaves RSA de 2048 bits.

| Escenario | `bancoseguro.test` publica | ¿Emisor firma DKIM? |
|---|---|---|
| `0` | Solo SOA, NS, A, MX | No |
| `1` | + `TXT "v=spf1 ip4:172.28.0.10 -all"` | No |
| `2` | + `s2026._domainkey` con la llave pública | Sí |
| `3-none` | + `_dmarc TXT "v=DMARC1; p=none; rua=mailto:dmarc-reportes@bancoseguro.test"` | Sí |
| `3-quarantine` | igual con `p=quarantine` | Sí |
| `3-reject` | igual con `p=reject` | Sí |
| `4` | igual que `3-reject` | Sí |
| `5` | `3-reject` + `noenvia.test` con `v=spf1 -all` y `p=reject` | Sí |

Infraestructura del atacante, presente en todos los escenarios:

- `atacante.test`: SPF `v=spf1 ip4:172.28.0.66 -all`, DKIM `a2026`, sin DMARC.
- `bancos3guro.test`: SPF `ip4:172.28.0.66`, DKIM `p2026` y DMARC `p=reject`. Es el dominio parecido "perfecto".

## 5. Catálogo de ataques

| ID | Descripción | MAIL FROM (sobre) | From: (visible) | Firma DKIM |
|---|---|---|---|---|
| A1 | Suplantación directa | director@bancoseguro.test | director@bancoseguro.test | ninguna |
| A2 | Sobre del atacante | rebote@atacante.test | director@bancoseguro.test | ninguna |
| A3 | Correo legítimo alterado | director@bancoseguro.test | director@bancoseguro.test | la original del banco, con el cuerpo modificado (cambia la cuenta bancaria) |
| A4 | Firma con su propio dominio | rebote@atacante.test | director@bancoseguro.test | `d=atacante.test` |
| A5 | Dominio parecido | director@bancos3guro.test | director@bancos3guro.test | `d=bancos3guro.test` |
| A6 | Solo el nombre visible | urgente@atacante.test | "Director General" <urgente@atacante.test> | `d=atacante.test` |

Todos van a `empleado@bancoseguro.test`, salen desde 172.28.0.66 y usan el mismo texto de "transferencia urgente". A3 toma el último correo legítimo firmado de Mailpit, cambia el número de cuenta en el cuerpo y lo reenvía tal cual.

**Extra del escenario 5 (fuera de la tabla de verdad y de `--todos`):** N1 · Dominio que no envía correo: `facturas@noenvia.test` en el sobre y en el `From:`, sin firma. Se entrega mientras `noenvia.test` no publica nada; con el escenario 5 (`v=spf1 -all` y `p=reject`) se rechaza.

## 6. Tabla de verdad (contrato de los tests)

`tests/test_matriz.py` debe verificar exactamente esto. Abreviaturas:

- **E:** entregado en Mailpit.
- **E+marca:** entregado con la marca de spam o cuarentena visible.
- **R:** rechazado con un SMTP 5xx.

| Envío | 0 | 1 | 2 | 3-none | 3-quarantine | 3-reject |
|---|---|---|---|---|---|---|
| Legítimo | E spf=none | E spf=pass | E dkim=pass | E dmarc=pass | E dmarc=pass | E dmarc=pass |
| A1 | E spf=none | E spf=fail | E spf=fail | E dmarc=fail | E+marca | R |
| A2 | E | E spf=pass (atacante.test) | E | E dmarc=fail | E+marca | R |
| A3 | E | E spf=fail | E dkim=fail | E dmarc=fail | E+marca | R |
| A4 | E | E | E dkim=pass (atacante.test) | E dmarc=fail | E+marca | R |
| A5 | E | E | E | E | E | E dmarc=pass (bancos3guro.test) |
| A6 | E | E | E | E | E | E |

Los escenarios 4 y 5 repiten la columna `3-reject`. Si la realidad contradice esta tabla, **no la cambies en silencio**: explica la causa y propón el ajuste.

## 7. CLI `lab`

Puntos de entrada en el host: `./lab.sh <comando>` (Linux, macOS, WSL) y `.\lab.ps1 <comando>` (PowerShell). Ambos delegan en `docker compose run --rm toolbox lab <comando>`, salvo los pasos que requieren reiniciar un servicio.

| Comando | Qué hace |
|---|---|
| `lab escenario <id>` | Activa el escenario: zona DNS, firma DKIM del emisor. Imprime en español qué cambió y el registro publicado |
| `lab enviar legit` | Envía el correo legítimo desde `emisor` |
| `lab atacar <A1..A6>` / `--todos` | Lanza ataques y muestra la respuesta SMTP resumida |
| `lab verificar` | `dig TXT` de los registros activos, con validación de sintaxis |
| `lab explicar ultimo` | Toma el último correo de la API de Mailpit y explica SPF, DKIM y DMARC en español, con colores |
| `lab reportes` | Muestra un reporte DMARC agregado de `reportes/ejemplos/` como tabla |
| `lab estado` | Escenario activo y salud de los servicios |
| `lab reset` | Vacía Mailpit y vuelve al escenario 0 |
| `lab reenviar [--lista]` | Escenario 5 (perfil `extras`): reenvía el último correo legítimo desde `reenviador`, tal cual o como una lista de correo que lo modifica |

## 8. Estructura del repositorio

```
email-auth-lab/
├── README.md  CLAUDE.md  LICENSE  SECURITY.md  CONTRIBUTING.md
├── .gitignore  .gitattributes  .env.example
├── docker-compose.yml
├── lab.sh  lab.ps1
├── init/                 # generación de llaves + render de zonas
├── dns/Corefile  dns/plantillas/        # zonas con marcadores {{DKIM_...}}
├── emisor/  receptor/  atacante/  toolbox/  reenviador/
├── escenarios/00-sin-proteccion … 05-extras/README.md
├── docs/teoria.md  implementacion-produccion.md  guion-presentacion.md
│   guia-de-uso.md  construir-desde-cero.md  solucion-de-problemas.md  glosario.md  img/
├── reportes/ejemplos/    # XML DMARC 100 % ficticios (IPs 192.0.2.0/24, dominios .test)
├── tests/
└── .github/workflows/ci.yml
```

Volúmenes en tiempo de ejecución (en `.gitignore`): `estado/`, `llaves/`, `zonas-render/`.

## 9. Convenciones

- Python 3.12, `ruff` (lint y formato), type hints, `pytest`. Scripts de shell con `set -euo pipefail` y que pasen `shellcheck`.
- Nombres de archivos y carpetas en español, como en la estructura. Identificadores de código en inglés. Mensajes al usuario, docs y comentarios explicativos en español.
- Mensajes de la CLI con colores (`rich`), cortos, y siempre diciendo **qué significa** el resultado, no solo el resultado.
- Imágenes con versión fija (nunca `latest`) para que el lab sea reproducible.
- Cada README de escenario tiene estas secciones: Objetivo · Qué se configura · Pasos · Resultado esperado · Qué aprendimos y qué sigue sin cubrirse · Preguntas para la audiencia.

## 10. Cómo verificar

```bash
docker compose build
docker compose up -d
./lab.sh estado
docker compose run --rm toolbox pytest -q
```

Definición de "terminado" para cada fase: compila, levanta, los tests de la fase pasan, el README del escenario existe y `git status` no muestra llaves, `.env` ni volúmenes.

## 11. Fases

1. **Esqueleto:** compose con `dns`, `receptor`, `mailpit`; un correo simple llega a Mailpit; test.
2. **Escenario 0:** `init`, `atacante`, `toolbox`, CLI (`escenario`, `atacar A1`, `reset`, `estado`), README 00.
3. **SPF:** escenario 1, A1 y A2, tests, README 01.
4. **DKIM:** `emisor` con OpenDKIM, escenario 2, A3 y A4, tests, README 02.
5. **DMARC:** escenarios 3-*, `lab reportes`, XML de ejemplo, tests, README 03.
6. **Límites:** escenario 4, A5 y A6, `lab explicar`, README 04 (y 05 si hay tiempo).
7. **Pulido:** README principal, docs/, SECURITY.md, CI, revisión de secretos, `docs/construir-desde-cero.md` sincronizado con el código real.

Trabaja **una fase a la vez**. Al terminar, resume qué se hizo, cómo se verificó y qué quedó pendiente, y propone el mensaje de commit.
