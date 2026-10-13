# Construir el laboratorio desde cero

Esta guía explica cómo construir `email-auth-lab` desde una computadora recién formateada hasta el repositorio publicado en GitHub. Si solo quieres **usar** el laboratorio, no necesitas esta guía: ve al `README.md` y sigue "Inicio rápido".

> **Cómo usar esta guía.** Cada fase dice qué se construye, por qué, qué archivos aparecen, el prompt para Claude Code y cómo comprobar que funciona. Si prefieres construirlo a mano, los prompts sirven como especificación. El código final del repositorio es la referencia definitiva; si algo aquí no coincide con él, manda el código.

---

## Índice

0. [Qué vas a construir](#0-qué-vas-a-construir)
1. [Preparar la computadora](#1-preparar-la-computadora)
2. [Crear el repositorio](#2-crear-el-repositorio)
3. [Fase 1: Esqueleto](#fase-1-esqueleto)
4. [Fase 2: Escenario 0, sin protección](#fase-2-escenario-0-sin-protección)
5. [Fase 3: SPF](#fase-3-spf)
6. [Fase 4: DKIM](#fase-4-dkim)
7. [Fase 5: DMARC](#fase-5-dmarc)
8. [Fase 6: Límites y explicador](#fase-6-límites-y-explicador)
9. [Fase 7: Pulido y documentación](#fase-7-pulido-y-documentación)
10. [Grabar evidencias para la presentación](#10-grabar-evidencias-para-la-presentación)
11. [Publicar en GitHub](#11-publicar-en-github)
12. [Problemas comunes](#12-problemas-comunes)

---

## 0. Qué vas a construir

Un entorno de Docker con **7 servicios** (más uno opcional) en una red **sin salida a Internet**: `init`, `dns`, `emisor`, `receptor`, `mailpit`, `atacante` y `toolbox`, más `reenviador` con el perfil `extras`. Un atacante intenta suplantar al director de *Banco Seguro* (`bancoseguro.test`), y tú activas SPF, DKIM y DMARC uno por uno hasta que el ataque es rechazado. La idea es ver:

- **Qué es** cada protocolo: el registro DNS y las cabeceras del correo.
- **Cómo se implementa**: la configuración real de Postfix, OpenDKIM y Rspamd.
- **De qué protege**: la matriz de ataques por escenario.
- **Qué no cubre**: dominios parecidos y suplantación del nombre visible.

Resultado final: `./lab.sh escenario 3-reject` + `./lab.sh atacar --todos` → A1 a A4 son rechazados con `554 5.7.1`, A5 y A6 siguen llegando (son los límites) y el correo legítimo pasa.

**Tiempo estimado:** 6 a 8 días de trabajo de medio tiempo con ayuda de Claude Code.

> Esta guía está sincronizada con el código final del repositorio. En cada fase, "Qué se construye" lista los archivos tal como quedaron. Cuando la construcción original se desvió del plan (por ejemplo, el `emisor` apareció en la fase 2 y no en la 3), se indica en una nota. Las salidas esperadas son reales; solo cambian los números de serial SOA, los identificadores de cola (`queued as …`) y los fragmentos de llaves.

---

## 1. Preparar la computadora

### 1.1 Requisitos de hardware

| Recurso | Mínimo | Recomendado |
|---|---|---|
| RAM | 8 GB | 16 GB |
| Disco libre | 10 GB | 20 GB |
| CPU | 64 bits con virtualización | 4 núcleos o más |
| Internet | Para instalar y para la primera construcción | Después, el lab funciona sin conexión |

### 1.2 Windows 10/11 (camino recomendado: todo dentro de WSL)

1. **Actualiza Windows** por completo y reinicia.
2. **Comprueba la virtualización.** Abre el Administrador de tareas, ve a Rendimiento, luego CPU, y busca "Virtualización: Habilitado". Si dice deshabilitado, entra a la BIOS y activa Intel VT-x o AMD-V/SVM.
3. **Instala WSL2 con Ubuntu.** En PowerShell **como administrador**:
   ```powershell
   wsl --install
   ```
   Reinicia. Al abrir Ubuntu por primera vez, crea tu usuario y contraseña de Linux.
4. **Instala Docker Desktop** desde https://www.docker.com/products/docker-desktop/ con la opción **WSL 2** marcada. Ábrelo y ve a *Settings → Resources → WSL Integration*. Activa tu distribución Ubuntu.
5. **Comprueba Docker desde Ubuntu:**
   ```bash
   docker run --rm hello-world
   docker compose version
   ```
   ✅ Debes ver "Hello from Docker!" y una versión de Compose v2.
6. **Instala las herramientas en Ubuntu:**
   ```bash
   sudo apt update && sudo apt install -y git dnsutils make curl
   ```
7. **Configura Git** (con tu correo *noreply* de GitHub: *Settings → Emails → Keep my email addresses private*):
   ```bash
   git config --global user.name "TU_USUARIO"
   git config --global user.email "NUMERO+TU_USUARIO@users.noreply.github.com"
   git config --global core.autocrlf input
   git config --global init.defaultBranch main
   ```
   `core.autocrlf input` evita que se cuelen finales de línea de Windows, que rompen los scripts dentro de los contenedores.
8. **Instala VS Code** en Windows con las extensiones *WSL*, *Docker* y *Python*. Abrirás el proyecto con *Connect to WSL*.
9. **Instala GitHub CLI** en Ubuntu siguiendo https://cli.github.com y autentícate:
   ```bash
   gh auth login   # GitHub.com → HTTPS → Login with a web browser
   ```
10. **Instala Claude Code** dentro de Ubuntu siguiendo la guía oficial: https://docs.claude.com/en/docs/claude-code/overview. Inicia sesión con tu cuenta.

### 1.3 macOS

1. Instala Docker Desktop (Apple Silicon o Intel según tu equipo).
2. Instala las herramientas: `xcode-select --install` para Git, y [Homebrew](https://brew.sh) para `brew install gh`.
3. Configura Git como en el paso 7 de Windows (sin `core.autocrlf`).
4. Instala VS Code y Claude Code.

### 1.4 Linux (Ubuntu/Debian)

1. Instala Docker Engine y el plugin Compose desde https://docs.docker.com/engine/install/. Agrega tu usuario al grupo `docker` y vuelve a iniciar sesión.
2. `sudo apt install -y git dnsutils make`, más `gh`, VS Code y Claude Code.

### 1.5 Comprobación final del entorno

```bash
docker --version && docker compose version && git --version && gh --version
```
✅ Los cuatro comandos responden con una versión. Si alguno falla, revisa la [sección 12](#12-problemas-comunes) antes de seguir.

---

## 2. Crear el repositorio

1. **Crea la carpeta** dentro de Linux, no en `C:\`. En Docker Desktop con WSL, la diferencia de velocidad es grande:
   ```bash
   mkdir -p ~/proyectos/email-auth-lab && cd ~/proyectos/email-auth-lab
   git init
   ```
2. **Copia `CLAUDE.md`** a la raíz, con ese nombre exacto: es el archivo que Claude Code lee solo en cada sesión. Es el contrato del proyecto: reglas, arquitectura, registros DNS y la tabla de verdad.
3. **Crea los archivos base** (o pídeselo a Claude Code en la fase 1):
   - `.gitattributes` → `* text=auto eol=lf`
   - `.gitignore` → `estado/`, `llaves/`, `zonas-render/`, `.env`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `*.eml`, `*.cast`, `.DS_Store`, `Thumbs.db`
   - `LICENSE` → MIT
4. **Abre el proyecto en VS Code** (`code .`) y, en una terminal de Ubuntu dentro de la carpeta, inicia Claude Code con `claude`.
5. **Primer prompt de calentamiento:**
   > Lee CLAUDE.md y resúmeme en 10 líneas el proyecto, las reglas no negociables y la tabla de verdad. Luego comprueba que Docker, Compose y Git funcionan en este entorno. No escribas código todavía.

   ✅ Si el resumen coincide con lo que esperas, Claude Code entendió el contexto.

**Forma de trabajo en cada fase:**

1. Pide primero un plan (modo plan) y revísalo.
2. Deja que construya **y ejecute** la fase.
3. Comprueba tú los resultados con los comandos de la sección "Verificación".
4. Haz commit:
   ```bash
   git add -A && git status   # revisa que no haya llaves, .env ni volúmenes
   git commit -m "Fase N: ..."
   ```

**Dos cosas que conviene saber desde el principio:**

- Los volúmenes (`llaves`, `estado`, `zonas-render`) son **volúmenes con nombre** de Docker, no carpetas del repo. Por eso nunca aparecen en `git status`. `docker compose down -v` los borra; sin `-v`, se conservan.
- La `toolbox` tiene `scale: 0`: `docker compose up -d --build` la **construye pero no la arranca**. Se usa bajo demanda con `./lab.sh <comando>` o `docker compose run --rm toolbox …`. Tiene IP fija (172.28.0.100), así que no se pueden correr dos a la vez.

---

## Fase 1: Esqueleto

**Objetivo:** un correo enviado al receptor aparece en la bandeja web. Es la base de todo lo demás.

**Qué se construye:**

- `docker-compose.yml` con `dns`, `receptor` y `mailpit`, la red `lab-net` (interna, `172.28.0.0/24`, IPs fijas) y la red `ui-net` solo para publicar Mailpit en `127.0.0.1:8025`.
- `dns/Corefile` y la zona mínima de `bancoseguro.test` (SOA, NS, A, MX → receptor, TTL 5).
- `receptor/`: `Dockerfile` (Debian trixie + Postfix + Rspamd), `main.cf`, `transport`, `entrypoint.sh` y `rspamd/` (`options.inc`, `milter_headers.conf`, `logging.inc`, `worker-controller.inc`).
- `toolbox/` mínima (Python 3.12, `dig`, pytest) y `tests/conftest.py` + `tests/test_fase1.py`.
- `pyproject.toml` (configuración de ruff y pytest).

**Prompt para Claude Code:**
> Lee CLAUDE.md. Fase 1. Crea el docker-compose con dns, receptor (Postfix + Rspamd como milter) y mailpit según la sección 3, con imágenes de versión fija. Respeta el detalle de las dos redes para publicar Mailpit. El receptor debe aceptar correo para bancoseguro.test y entregarlo a Mailpit con la cabecera Authentication-Results agregada por Rspamd. Agrega un test que envíe un correo simple y lo encuentre en la API de Mailpit. Usa modo plan primero, luego construye, levanta todo y corre el test.

> **Punto clave de esta fase:** Rspamd trata las IPs privadas como "locales" y **se salta SPF y DMARC**. El síntoma es `Authentication-Results: …; none` y, en `docker compose logs receptor`, `skip SPF checks for local networks`. No basta con `local_addrs`: hace falta además `check_local = true` en `receptor/rspamd/options.inc`.

**Verificación:**
```bash
docker compose up -d --build
docker compose ps                                        # receptor y mailpit «healthy», dns «Up»
docker compose run --rm toolbox pytest -q tests/test_fase1.py
```
✅ `5 passed`. En http://localhost:8025 hay un correo de prueba, y en *Headers* aparece:
```
Authentication-Results: receptor.bancoseguro.test; dkim=none; dmarc=none; spf=none (receptor.bancoseguro.test: domain of prueba@bancoseguro.test has no SPF policy when checking 172.28.0.100) smtp.mailfrom=prueba@bancoseguro.test
```

> **Punto de decisión.** Si al cierre del día Rspamd no agrega `Authentication-Results` con resultados reales, cambia a un receptor en Python (`aiosmtpd` + `dkimpy` + `pyspf` + `authres`). Pídeselo así a Claude Code: *"Reemplaza Rspamd por un receptor en Python que haga las mismas verificaciones y aplique DMARC; mantén la misma interfaz y tests"*. Documenta la decisión en el README. (En la construcción original no hizo falta.)

---

## Fase 2: Escenario 0, sin protección

**Objetivo:** demostrar el problema. El atacante se hace pasar por el director y el correo llega sin ninguna alerta.

**Qué se construye:**

- `init/`: `Dockerfile` (Python 3.12 + opendkim-tools), `entrypoint.sh` (genera las llaves `s2026`, `a2026` y `p2026` de 2048 bits si faltan) y `renderizar_zonas.py`. Este último renderiza las zonas de **todos** los escenarios en el volumen `zonas-render` y activa el escenario guardado en `estado/estado.json`.
- `dns/plantillas/`: `db.bancoseguro.test`, `db.atacante.test` y `db.bancos3guro.test`, con los marcadores `{{SERIAL}}`, `{{REGISTROS_ESCENARIO}}` y `{{DKIM_…}}`. El Corefile sirve `/zonas/activas/` y recarga cada 2 s cuando cambia el serial.
- `atacante/`: `Dockerfile` (Debian + swaks + Python), `servidor.py` (API HTTP solo dentro de `lab-net`) y `ataques/` (`comun.py`, con la validación de destino, y `a1_spoof_directo.py`).
- `toolbox/`: el paquete `lab` (`cli.py`, `config.py`, `dns.py`, `mailpit.py`, `escenarios.py`, `envios.py`, `servicios.py`), `pyproject.toml` y `requirements.txt` (pytest, rich).
- `lab.sh` y `lab.ps1`.
- `tests/test_fase2.py` y `tests/test_matriz.py`, con la tabla de verdad completa copiada de CLAUDE.md.
- `escenarios/00-sin-proteccion/README.md`.

> **Nota sobre la construcción original:** aquí también se agregaron `emisor/` (Postfix sin DKIM) y `lab enviar legit`, que el plan dejaba para la fase 3. La fila "Legítimo" de la columna 0 necesita un servidor del banco en 172.28.0.10.

**Cómo funciona el cambio de escenario sin `docker.sock`:** `lab escenario <id>` copia las zonas ya renderizadas a `zonas-render/activas/` con un serial nuevo y escribe `estado/estado.json`. CoreDNS ve el serial y recarga la zona. Los demás contenedores leen el estado del volumen compartido.

**Prompt:**
> Fase 2 de CLAUDE.md. Agrega los servicios init, atacante y toolbox, la CLI lab con escenario, atacar A1, reset y estado, y los wrappers lab.sh y lab.ps1. Implementa el escenario 0 y el ataque A1. El cambio de escenario debe funcionar sin docker.sock, como dice la sección 3. Agrega tests para la fila A1 y la fila "Legítimo" en la columna 0 de la tabla de verdad, y escribe el README del escenario 00 con la plantilla de la sección 9.

**Verificación:**
```bash
docker compose up -d --build
./lab.sh estado
./lab.sh escenario 0
./lab.sh atacar A1
docker compose run --rm toolbox pytest -q tests/test_fase2.py    # 14 passed
```
✅ `./lab.sh atacar A1` muestra:
```
A1 · Suplantación directa
  Sobre (MAIL FROM): director@bancoseguro.test
  Remitente visible (From:): director@bancoseguro.test
  Firma DKIM: ninguna
  Respuesta SMTP: 250 2.0.0 Ok: queued as 8C0984F08B
  ACEPTADO: el receptor recibió el correo para entregarlo.
  Llegó a la bandeja del empleado (Mailpit).  spf=none  dkim=none  dmarc=none
  Qué significa: bancoseguro.test no publica SPF: no hay nada que verificar.
  Qué significa: Sin firma DKIM.
  Qué significa: bancoseguro.test no publica DMARC: no hay política que aplicar.
```
En Mailpit aparece "Transferencia urgente" de `director@bancoseguro.test`.

Comprueba también la regla 3: `./lab.sh atacar A1 --para alguien@gmail.com` debe responder `✗ Destinatario no permitido: «alguien@gmail.com». Este laboratorio solo envía correo a dominios .test (RFC 2606). No se envió nada.`

---

## Fase 3: SPF

**Objetivo:** publicar quién puede enviar por `bancoseguro.test`, y mostrar su límite: SPF valida el sobre, no el `From:` que ve el usuario.

**Qué se construye:**

- El escenario 1 en `init/renderizar_zonas.py`: `@ IN TXT "v=spf1 ip4:172.28.0.10 -all"`.
- `atacante/ataques/a2_sobre_atacante.py`.
- `receptor/rspamd/spf.conf` (`min_cache_ttl = 1s`).
- En `toolbox/lab/escenarios.py`, la espera de un TTL (5 s) cuando cambia una zona, y en la CLI la interpretación de SPF.
- `tests/test_fase3.py` y las celdas de la columna 1 en `tests/test_matriz.py`.
- `escenarios/01-spf/README.md`.

> **Notas sobre la construcción original:** la zona de `atacante.test` (con su SPF), el `emisor` y `lab enviar legit` ya existían desde la fase 2. El problema real de esta fase fue la **caché de SPF de Rspamd**: guarda los registros un mínimo de 5 minutos aunque el TTL sea de 5 s. Sin `spf.conf`, al volver del escenario 1 al 0 el ataque seguía dando `spf=fail`.

**Prompt:**
> Fase 3 de CLAUDE.md. Agrega el servicio emisor (sin DKIM aún) y el comando enviar legit. Implementa el escenario 1, la zona de atacante.test y el ataque A2. Tests para las columnas 0 y 1 de la tabla de verdad. README del escenario 01, explicando por qué A2 obtiene spf=pass.

**Verificación:**
```bash
./lab.sh escenario 1
./lab.sh verificar           # muestra y valida el TXT de SPF
./lab.sh enviar legit        # spf=pass
./lab.sh atacar A1 A2        # A1: spf=fail, pero llega · A2: spf=pass para atacante.test
docker compose run --rm toolbox pytest -q tests/test_fase3.py    # 7 passed
```
✅ `./lab.sh escenario 1` muestra el cambio y la espera del TTL:
```
Cambios en el DNS respecto al escenario 0:
  + @ IN TXT "v=spf1 ip4:172.28.0.10 -all"
Esperé 5 s (el TTL de la zona) para que el receptor no use registros viejos de su caché.
```
Y A2:
```
A2 · Sobre del atacante
  Sobre (MAIL FROM): rebote@atacante.test
  Remitente visible (From:): director@bancoseguro.test
  …
  Llegó a la bandeja del empleado (Mailpit).  spf=pass  dkim=none  dmarc=none
  Qué significa: SPF pasó, pero para atacante.test (el sobre), no para bancoseguro.test, que es lo que ve el empleado. SPF no compara esos dos dominios.
```

---

## Fase 4: DKIM

**Objetivo:** firmar el correo legítimo y demostrar integridad. También mostrar el límite: un atacante puede firmar con su propio dominio.

**Qué se construye:**

- `emisor/`:
  - `opendkim.conf` (selector `s2026`, `relaxed/relaxed`, `SignHeaders` con `Date`, `Message-ID` y MIME, `From` sobrefirmado);
  - `entrypoint.sh`, que vigila `estado/estado.json`, pone o quita OpenDKIM con `postfix reload` y confirma en `estado/emisor.json`.
- El escenario 2: SPF + `s2026._domainkey`.
- Montajes de llaves con `subpath` en `docker-compose.yml`: el emisor solo recibe la del banco y el atacante solo las suyas.
- `atacante/entrypoint.sh` (copia sus llaves y baja privilegios). El atacante ahora arma el mensaje en Python (dkimpy) y swaks lo envía tal cual.
- `atacante/ataques/a3_legitimo_alterado.py` y `a4_firma_propia.py`.
- `tests/test_fase4.py`, la columna 2 y `escenarios/02-dkim/README.md`.

> **Notas sobre la construcción original:** la llave `a2026` de `atacante.test` ya estaba publicada desde la fase 2. Hubo dos problemas:
> - Un comentario de la plantilla contenía `{{REGISTROS_ESCENARIO}}`, que también se reemplazaba, y **duplicaba el registro DKIM**. Ahora el renderizador falla si un comentario tiene un marcador.
> - La primera firma solo cubría `From:To:Subject`. Se agregó `SignHeaders`, y `lab enviar legit` ahora pone `Date`.

**Prompt:**
> Fase 4 de CLAUDE.md. Configura OpenDKIM en el emisor con selector s2026, firmando solo en escenarios ≥ 2. Publica la llave en la zona del escenario 2 y agrega la llave a2026 de atacante.test. Implementa A3 (toma el último correo legítimo firmado de Mailpit, cambia la cuenta bancaria en el cuerpo y lo reenvía) y A4. Tests de la columna 2. README del escenario 02, explicando los campos d=, s=, bh= y b=.

**Verificación:**
```bash
docker compose up -d --build
./lab.sh escenario 2         # «Firma DKIM del emisor: activada (confirmado por el emisor)»
./lab.sh enviar legit        # spf=pass  dkim=pass
./lab.sh atacar A3 A4
docker compose run --rm toolbox pytest -q tests/test_fase4.py    # 10 passed
git status                   # ¡ninguna llave en la lista!
```
✅ A3 y A4:
```
A3 · Correo legítimo alterado
  …
  Usé el último correo legítimo firmado por bancoseguro.test y cambié la cuenta.
  Llegó a la bandeja del empleado (Mailpit).  spf=fail  dkim=fail  dmarc=none
  Qué significa: DKIM falló: la firma de bancoseguro.test no coincide con el contenido. El correo fue modificado después de firmarse.

A4 · Firma con su propio dominio
  …
  Llegó a la bandeja del empleado (Mailpit).  spf=pass  dkim=pass  dmarc=none
  Qué significa: DKIM válido, pero firmado por atacante.test, no por bancoseguro.test. Prueba quién firmó, no que el remitente visible sea auténtico.
```
En *Headers* de A3: `dkim=fail ("body hash did not verify") header.d=bancoseguro.test header.s=s2026`.

---

## Fase 5: DMARC

**Objetivo:** unir SPF y DKIM con el `From:` visible (alineación), decirle al receptor qué hacer y obtener reportes.

**Qué se construye:**

- Los escenarios `3-none`, `3-quarantine` y `3-reject`: SPF + DKIM + `_dmarc "v=DMARC1; p=…; rua=mailto:dmarc-reportes@bancoseguro.test"`.
- `receptor/rspamd/`:
  - `dmarc.conf`: `actions { reject = "reject"; quarantine = "rewrite subject"; }`, según la [documentación de Rspamd](https://docs.rspamd.com/modules/dmarc/);
  - `actions.conf`: acciones por puntaje desactivadas y `subject = "[CUARENTENA] %s"`;
  - `worker-proxy.inc`: mensaje de rechazo en español.
- `lab reportes` (`toolbox/lab/reportes.py`) y `reportes/ejemplos/receptor-ejemplo.test!bancoseguro.test!1791763200!1791849600.xml` (100 % ficticio).
- `tests/test_fase5.py`, las columnas 3-* y `escenarios/03-dmarc/README.md`.

> **Nota sobre la construcción original:** `lab atacar --todos` existía desde la fase 2. Las acciones por puntaje se desactivaron porque A3 (SPF y DKIM fallidos) ya sumaba puntos de "greylist". Sin ese cambio, las celdas "E" podían salir marcadas por puntaje y no por DMARC.

**Prompt:**
> Fase 5 de CLAUDE.md. Implementa los escenarios 3-none, 3-quarantine y 3-reject. El receptor debe marcar en quarantine y rechazar con 5xx en reject; confirma la configuración vigente de Rspamd en su documentación. Agrega atacar --todos, lab reportes y un XML de reporte agregado de ejemplo, 100 % ficticio. Tests de las columnas 3-*. README del escenario 03, con la ruta none → quarantine → reject tal como se hace en producción.

**Verificación:**
```bash
docker compose up -d --build
./lab.sh escenario 3-none        && ./lab.sh atacar --todos   # todo entra; A1–A4 con dmarc=fail
./lab.sh escenario 3-quarantine  && ./lab.sh atacar --todos   # A1–A4: «Llegó MARCADO como sospechoso»
./lab.sh escenario 3-reject      && ./lab.sh atacar --todos   # A1–A4 rechazados
./lab.sh enviar legit                                          # dmarc=pass
./lab.sh reportes
docker compose run --rm toolbox pytest -q tests/test_fase5.py  # 13 passed
```
✅ En `3-reject`:
```
A1 · Suplantación directa
  Respuesta SMTP: 554 5.7.1 Rechazado por la politica DMARC (p=reject) del dominio del remitente
  RECHAZADO: el receptor lo bloqueó en la conversación SMTP. El correo nunca llegó a la bandeja del empleado.
```
Y `./lab.sh reportes` termina con:
```
Resumen: 1590 de 2091 correos pasan DMARC (76 %). Con p=reject se rechazarían 501.
Ojo: 412 de esos correos parecen legítimos (un servicio sin alinear). Corrígelo antes de pasar a quarantine o reject.
```

---

## Fase 6: Límites y explicador

**Objetivo:** mostrar con honestidad lo que estos protocolos **no** cubren, y dar una herramienta que traduzca las cabeceras a español.

**Qué se construye:**

- El escenario 4 (los mismos registros que `3-reject`).
- `atacante/ataques/a5_dominio_parecido.py` (firma `d=bancos3guro.test`) y `a6_nombre_visible.py`.
- `lab explicar ultimo` (`toolbox/lab/explicador.py`), que también detecta dominios parecidos y nombres visibles engañosos. `lab atacar` acepta varios ataques a la vez.
- `tests/test_fase6.py`, A5 y A6 en todas las columnas, la columna 4 y `escenarios/04-limites/README.md`.
- **Escenario 5 (opcional):**
  - `dns/plantillas/db.noenvia.test` y la zona en el Corefile;
  - `atacante/ataques/n1_dominio_que_no_envia.py` (extra: no entra en `--todos`);
  - `reenviador/` (`Dockerfile` y `servidor.py`, perfil `extras`), que reutiliza `comun.py` del atacante con `additional_contexts`;
  - `lab reenviar [--lista]`;
  - `tests/test_escenario5.py`, la columna 5 y `escenarios/05-extras/README.md`.

> **Notas sobre la construcción original:** la zona de `bancos3guro.test` (SPF, DKIM `p2026`, DMARC `p=reject`) existía desde la fase 2. Hubo dos problemas:
> - CoreDNS no veía la zona nueva porque leía el Corefile solo al arrancar. Ahora se monta la carpeta `dns/` y el Corefile usa el plugin `reload`.
> - `lab escenario` solo comparaba la zona del banco para decidir si esperar el TTL. Ahora compara todas.

**Prompt:**
> Fase 6 de CLAUDE.md. Agrega bancos3guro.test, los ataques A5 y A6, y el comando explicar ultimo: debe leer el último correo de la API de Mailpit y explicar en español, con colores, el resultado de SPF, DKIM y DMARC y qué significa cada uno. Tests de A5 y A6 en 3-reject. README del escenario 04. Si todo pasa, implementa el escenario 5 opcional.

**Verificación:**
```bash
docker compose --profile extras up -d --build --wait     # incluye el reenviador
./lab.sh escenario 4
./lab.sh atacar A5 && ./lab.sh explicar ultimo           # pasa todo: es SU dominio
./lab.sh atacar A6 && ./lab.sh explicar ultimo
./lab.sh escenario 5 && ./lab.sh atacar N1               # 554: noenvia.test está protegido
./lab.sh enviar legit && ./lab.sh reenviar               # spf=fail  dkim=pass  dmarc=pass
docker compose run --rm toolbox pytest -q tests/test_fase6.py tests/test_escenario5.py   # 23 passed
```
✅ La conclusión de `./lab.sh explicar ultimo` después de A5:
```
Conclusión
   ⚠ Dominio parecido: bancos3guro.test imita a bancoseguro.test. SPF, DKIM y DMARC pueden pasar porque el correo es auténtico… de bancos3guro.test. Ninguno compara dominios «parecidos».
   DMARC pasó, pero solo garantiza que el correo viene de bancos3guro.test. Decide tú si ese dominio es quien dice ser.
```
Y después de A6:
```
Conclusión
   ⚠ Nombre visible: dice «Director General», pero la dirección real es urgente@atacante.test. Muchos clientes (sobre todo en el móvil) muestran solo el nombre, y nadie verifica el nombre.
   atacante.test no publica DMARC: nada garantiza que el remitente visible sea auténtico.
```

---

## Fase 7: Pulido y documentación

**Objetivo:** que cualquier persona pueda clonar, entender y usar el lab sin ti.

**Qué se construye:**

- `README.md`: qué es, aviso de uso ético, inicio rápido, escenarios, ataques, tabla de verdad, comandos, arquitectura (Mermaid), tests, limitaciones y créditos.
- `docs/`:
  - `teoria.md` (con diagramas Mermaid), `implementacion-produccion.md`, `guion-presentacion.md`, `solucion-de-problemas.md` y `glosario.md`;
  - `img/`, con capturas SVG de la salida real de la CLI.
- `SECURITY.md`, `CONTRIBUTING.md` y `.env.example` (`MAILPIT_PUERTO`, `COMPOSE_PROFILES`).
- `.github/workflows/ci.yml`:
  - **calidad:** ruff, shellcheck, sintaxis de `lab.ps1`, finales de línea, gitleaks y puertos en `127.0.0.1`;
  - **laboratorio:** levanta con `--profile extras`, corre `lab estado` y pytest, y comprueba que `git status` quede limpio.
- `lab verificar` (`toolbox/lab/verificar.py`), que estaba en la tabla de la CLI de CLAUDE.md y faltaba, y `tests/test_fase7.py`.
- `toolbox/lab/capturas.py`, que regenera las capturas de `docs/img/`.
- Revisión de secretos en todo el historial y **esta guía, sincronizada con el código real**.

**Prompt:**
> Fase 7 de CLAUDE.md. Revisa el repo como si fueras a publicarlo. Escribe el README principal y los documentos de docs/. Crea SECURITY.md, CONTRIBUTING.md y el workflow de CI. Revisa todo el historial y los archivos en busca de secretos o llaves. Por último, actualiza docs/construir-desde-cero.md para que cada comando, archivo y salida esperada coincida exactamente con el código final.

**Verificación:**
```bash
./lab.sh verificar
docker run --rm -v "$PWD":/repo zricethezav/gitleaks:v8.28.0 git /repo --redact   # «no leaks found»
docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:1.7.7                   # sin salida = sin errores
```

**La prueba de fuego:** un clon limpio tiene que pasar todos los tests sin pasos manuales extra. El proyecto se llama `email-auth-lab` y usa la subred 172.28.0.0/24, así que primero baja tu copia de trabajo (sin `-v`, para conservar sus llaves) y usa otro nombre de proyecto en el clon:
```bash
docker compose --profile extras down
git clone ~/proyectos/email-auth-lab /tmp/prueba && cd /tmp/prueba
docker compose -p prueba --profile extras up -d --build --wait
docker compose -p prueba run --rm toolbox pytest -q          # 154 passed
docker compose -p prueba --profile extras down -v
cd ~/proyectos/email-auth-lab && docker compose up -d
```
✅ `154 passed` en unos 9 minutos. Esto demuestra que el lab es replicable.

---

## 10. Grabar evidencias para la presentación

Las demos en vivo fallan; ten todo grabado.

- **Capturas de la CLI:** `docker compose run --rm -v ./docs/img:/salida toolbox python -m lab.capturas /salida` regenera los SVG de `docs/img/` con la salida real (escenario 0 con A1, `3-reject` con `--todos`, A5 con `explicar` y `reportes`). Cambia escenarios y vacía Mailpit: úsalo con el laboratorio en reposo.
- **Terminal en video:** `asciinema rec escenario-3.cast` dentro de Ubuntu (instálalo con `sudo apt install asciinema`) y conviértelo a GIF con `agg`. Los `.cast` están en `.gitignore`.
- **Mailpit:** en Windows usa ScreenToGif; en macOS, `Cmd+Shift+5`.
- Usa una fuente de terminal de 20 pt o más, y modo claro, para proyectar.
- **Sin Internet en el evento:** construye el día anterior. Para repartir el lab, exporta las imágenes:
  ```bash
  docker save $(docker compose --profile extras config --images) -o email-auth-lab-imagenes.tar
  # en otra máquina: docker load -i email-auth-lab-imagenes.tar
  ```

El guion completo de la charla está en [guion-presentacion.md](guion-presentacion.md).

---

## 11. Publicar en GitHub

1. **Última revisión:**
   ```bash
   git status                                       # limpio: sin llaves, .env ni volúmenes
   git log --all -p | grep -c "PRIVATE KEY"         # debe imprimir 0
   docker run --rm -v "$PWD":/repo zricethezav/gitleaks:v8.28.0 git /repo --redact
   ```
2. **Crea el repositorio y súbelo** (si todavía no tiene remoto):
   ```bash
   gh repo create email-auth-lab --public --source=. --remote=origin \
     --description "Laboratorio local de SPF, DKIM y DMARC: qué son, cómo se implementan y de qué protegen" --push
   ```
   Si el remoto ya existe: `git push -u origin main`.
3. En GitHub:
   - ve a *Settings → Advanced Security* y activa **Secret Protection** y **Push protection**;
   - activa también **Private vulnerability reporting**, que es el canal que indica `SECURITY.md`.
4. En el engrane de *About*, agrega los topics: `email-security`, `spf`, `dkim`, `dmarc`, `phishing`, `bec`, `blue-team`, `docker`, `lab`.
5. Revisa que el workflow **CI** pase en verde en la pestaña *Actions*.
6. **Release:**
   ```bash
   git tag v1.0.0 && git push --tags
   gh release create v1.0.0 --title "v1.0.0" --notes "Primera versión pública del laboratorio"
   ```

> Si alguna vez subes una llave por error, no basta con borrar el commit:
> - regenera las llaves con `docker compose down -v && docker compose up -d`;
> - limpia el historial (`git filter-repo`);
> - fuerza el push.
>
> Las llaves del laboratorio solo valen para dominios `.test`, pero es un buen hábito.

---

## 12. Problemas comunes

| Síntoma | Causa probable | Solución |
|---|---|---|
| Docker Desktop no arranca en Windows | Virtualización apagada o WSL2 sin instalar | Activa VT-x/AMD-V en la BIOS y corre `wsl --install` |
| `docker: command not found` en Ubuntu | Falta la integración con WSL | Docker Desktop → *Settings → Resources → WSL Integration* |
| Los scripts fallan con `\r: command not found` | Finales de línea CRLF | `git config --global core.autocrlf input` y vuelve a clonar; revisa `.gitattributes` |
| `localhost:8025` no abre | Puerto ocupado | Copia `.env.example` a `.env`, cambia `MAILPIT_PUERTO` y corre `docker compose up -d` |
| `Authentication-Results: …; none` | Rspamd considera la red como local | `local_addrs` **y** `check_local = true` en `receptor/rspamd/options.inc` (fase 1) |
| El cambio de escenario no se nota | Caché de SPF de Rspamd o una zona sin recargar | `./lab.sh verificar`; revisa `receptor/rspamd/spf.conf` y `docker compose logs dns` |
| `Address already in use` al correr `./lab.sh` | Otra toolbox en marcha (IP fija) | Espera a que termine (por ejemplo, los tests) |
| Construcción muy lenta en Windows | Proyecto en `C:\` y no en WSL | Mueve el proyecto a `~/proyectos/` dentro de Ubuntu |

La lista completa, con la explicación de cada decisión de configuración, está en [solucion-de-problemas.md](solucion-de-problemas.md).
