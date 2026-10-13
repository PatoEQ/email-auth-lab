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

Un entorno con 7 contenedores Docker en una red **sin salida a Internet**. Un atacante intenta suplantar al director de *Banco Seguro* (`bancoseguro.test`), y tú activas SPF, DKIM y DMARC uno por uno hasta que el ataque es rechazado. La idea es ver:

- **Qué es** cada protocolo: el registro DNS y las cabeceras del correo.
- **Cómo se implementa**: la configuración real de Postfix, OpenDKIM y Rspamd.
- **De qué protege**: la matriz de ataques por escenario.
- **Qué no cubre**: dominios parecidos y suplantación del nombre visible.

Resultado final: `./lab.sh escenario 3-reject` + `./lab.sh atacar --todos` → los ataques A1 a A4 son rechazados y el correo legítimo sigue llegando.

**Tiempo estimado:** 6 a 8 días de trabajo de medio tiempo con ayuda de Claude Code.

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
2. **Copia `CLAUDE.md`** a la raíz. Es el contrato del proyecto: reglas, arquitectura, registros DNS y la tabla de verdad. Claude Code lo lee en cada sesión.
3. **Crea los archivos base** (o pídeselo a Claude Code en la fase 1):
   - `.gitattributes` → `* text=auto eol=lf`
   - `.gitignore` → `estado/`, `llaves/`, `zonas-render/`, `.env`, `__pycache__/`, `.pytest_cache/`, `*.eml`
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
   git add . && git status   # revisa que no haya llaves, .env ni volúmenes
   git commit -m "Fase N: ..."
   ```

---

## Fase 1: Esqueleto

**Objetivo:** un correo enviado al receptor aparece en la bandeja web. Es la base de todo lo demás.

**Qué se construye:**

- `docker-compose.yml` con `dns`, `receptor` y `mailpit`, la red `lab-net` (interna, `172.28.0.0/24`) y la red `ui-net` solo para publicar la interfaz de Mailpit en `127.0.0.1:8025`.
- `dns/`: Corefile de CoreDNS y la zona mínima de `bancoseguro.test` (SOA, NS, A, MX → receptor).
- `receptor/`: Postfix que acepta correo para `bancoseguro.test` y lo pasa a `mailpit:1025`. Rspamd conectado como milter, todavía sin políticas.
- `tests/test_fase1.py`: envía un correo y lo busca en la API de Mailpit.

**Prompt para Claude Code:**
> Lee CLAUDE.md. Fase 1. Crea el docker-compose con dns, receptor (Postfix + Rspamd como milter) y mailpit según la sección 3, con imágenes de versión fija. Respeta el detalle de las dos redes para publicar Mailpit. El receptor debe aceptar correo para bancoseguro.test y entregarlo a Mailpit con la cabecera Authentication-Results agregada por Rspamd. Agrega un test que envíe un correo simple y lo encuentre en la API de Mailpit. Usa modo plan primero, luego construye, levanta todo y corre el test.

**Verificación:**
```bash
docker compose up -d --build
docker compose ps                      # todos "running" o "healthy"
docker compose run --rm toolbox pytest -q tests/test_fase1.py   # o el comando que defina la fase
```
✅ Abre http://localhost:8025: hay un correo de prueba, y en *Headers* aparece `Authentication-Results`.

> **Punto de decisión.** Si al cierre del día Rspamd no agrega `Authentication-Results` con resultados reales, cambia a un receptor en Python (`aiosmtpd` + `dkimpy` + `pyspf` + `authres`). Pídeselo así a Claude Code: *"Reemplaza Rspamd por un receptor en Python que haga las mismas verificaciones y aplique DMARC; mantén la misma interfaz y tests"*. Documenta la decisión en el README.

---

## Fase 2: Escenario 0, sin protección

**Objetivo:** demostrar el problema. El atacante se hace pasar por el director y el correo llega sin ninguna alerta.

**Qué se construye:**

- `init/`: contenedor que genera las llaves DKIM (2048 bits) si no existen y renderiza las zonas DNS desde `dns/plantillas/`, sustituyendo las llaves públicas. Las llaves van a un volumen ignorado por Git.
- `atacante/`: imagen con `swaks` y `ataques/a1_spoof_directo.py`, que valida que el destino sea `.test`.
- `toolbox/`: imagen con la CLI `lab` (`escenario`, `atacar`, `reset`, `estado`).
- `lab.sh` y `lab.ps1` en la raíz.
- `escenarios/00-sin-proteccion/README.md`.

**Prompt:**
> Fase 2 de CLAUDE.md. Agrega los servicios init, atacante y toolbox, la CLI lab con escenario, atacar A1, reset y estado, y los wrappers lab.sh y lab.ps1. Implementa el escenario 0 y el ataque A1. El cambio de escenario debe funcionar sin docker.sock, como dice la sección 3. Agrega tests para la fila A1 y la fila "Legítimo" en la columna 0 de la tabla de verdad, y escribe el README del escenario 00 con la plantilla de la sección 9.

**Verificación:**
```bash
./lab.sh escenario 0
./lab.sh atacar A1
```
✅ En Mailpit aparece "Transferencia urgente" de `director@bancoseguro.test`, con `spf=none`, `dkim=none` y `dmarc=none`.

---

## Fase 3: SPF

**Objetivo:** publicar quién puede enviar por `bancoseguro.test`, y mostrar su límite: SPF valida el sobre, no el `From:` que ve el usuario.

**Qué se construye:**

- La zona del escenario 1 con `v=spf1 ip4:172.28.0.10 -all`.
- La zona de `atacante.test`, con su propio SPF.
- El servicio `emisor` (Postfix, sin DKIM todavía) y `lab enviar legit`.
- El ataque A2 (`a2_sobre_atacante.py`).
- Tests de las columnas 0 y 1 para Legítimo, A1 y A2.
- `escenarios/01-spf/README.md`.

**Prompt:**
> Fase 3 de CLAUDE.md. Agrega el servicio emisor (sin DKIM aún) y el comando enviar legit. Implementa el escenario 1, la zona de atacante.test y el ataque A2. Tests para las columnas 0 y 1 de la tabla de verdad. README del escenario 01, explicando por qué A2 obtiene spf=pass.

**Verificación:**
```bash
./lab.sh escenario 1
./lab.sh verificar           # muestra el TXT de SPF
./lab.sh enviar legit        # spf=pass
./lab.sh atacar A1           # spf=fail, pero llega
./lab.sh atacar A2           # spf=pass para atacante.test, el usuario ve al director
```

---

## Fase 4: DKIM

**Objetivo:** firmar el correo legítimo y demostrar integridad. También mostrar el límite: un atacante puede firmar con su propio dominio.

**Qué se construye:**

- OpenDKIM en `emisor`, que firma solo cuando el escenario es 2 o mayor.
- El registro `s2026._domainkey.bancoseguro.test` en la zona del escenario 2.
- La llave `a2026` de `atacante.test`.
- Los ataques A3 (`a3_alterado.py`) y A4 (`a4_firma_propia.py`).
- Tests de la columna 2 y `escenarios/02-dkim/README.md`.

**Prompt:**
> Fase 4 de CLAUDE.md. Configura OpenDKIM en el emisor con selector s2026, firmando solo en escenarios ≥ 2. Publica la llave en la zona del escenario 2 y agrega la llave a2026 de atacante.test. Implementa A3 (toma el último correo legítimo firmado de Mailpit, cambia la cuenta bancaria en el cuerpo y lo reenvía) y A4. Tests de la columna 2. README del escenario 02, explicando los campos d=, s=, bh= y b=.

**Verificación:**
```bash
./lab.sh escenario 2
./lab.sh enviar legit        # dkim=pass, cabecera DKIM-Signature visible
./lab.sh atacar A3           # dkim=fail (body hash did not verify)
./lab.sh atacar A4           # dkim=pass, pero para atacante.test
git status                   # ¡ninguna llave en la lista!
```

---

## Fase 5: DMARC

**Objetivo:** unir SPF y DKIM con el `From:` visible (alineación), decirle al receptor qué hacer y obtener reportes.

**Qué se construye:**

- Las zonas `3-none`, `3-quarantine` y `3-reject`.
- La aplicación de la política en el receptor (marca en cuarentena, rechazo 5xx).
- `lab reportes` y `reportes/ejemplos/agregado-ejemplo.xml` (ficticio).
- `lab atacar --todos`.
- Tests de las columnas 3-*.
- `escenarios/03-dmarc/README.md`.

**Prompt:**
> Fase 5 de CLAUDE.md. Implementa los escenarios 3-none, 3-quarantine y 3-reject. El receptor debe marcar en quarantine y rechazar con 5xx en reject; confirma la configuración vigente de Rspamd en su documentación. Agrega atacar --todos, lab reportes y un XML de reporte agregado de ejemplo, 100 % ficticio. Tests de las columnas 3-*. README del escenario 03, con la ruta none → quarantine → reject tal como se hace en producción.

**Verificación:**
```bash
./lab.sh escenario 3-none        && ./lab.sh atacar --todos   # todo entra, dmarc=fail
./lab.sh escenario 3-quarantine  && ./lab.sh atacar --todos   # entra marcado
./lab.sh escenario 3-reject      && ./lab.sh atacar --todos   # A1–A4 rechazados (5xx)
./lab.sh enviar legit                                          # dmarc=pass
./lab.sh reportes
```

---

## Fase 6: Límites y explicador

**Objetivo:** mostrar con honestidad lo que estos protocolos **no** cubren, y dar una herramienta que traduzca las cabeceras a español.

**Qué se construye:**

- La zona de `bancos3guro.test` (SPF, DKIM `p2026`, DMARC `p=reject`).
- Los ataques A5 (dominio parecido) y A6 (nombre visible).
- `lab explicar ultimo`.
- Tests de A5 y A6.
- `escenarios/04-limites/README.md` y, si hay tiempo, el escenario 5 (servicio `reenviador` con el perfil `extras`, más `noenvia.test`).

**Prompt:**
> Fase 6 de CLAUDE.md. Agrega bancos3guro.test, los ataques A5 y A6, y el comando explicar ultimo: debe leer el último correo de la API de Mailpit y explicar en español, con colores, el resultado de SPF, DKIM y DMARC y qué significa cada uno. Tests de A5 y A6 en 3-reject. README del escenario 04. Si todo pasa, implementa el escenario 5 opcional.

**Verificación:**
```bash
./lab.sh escenario 4
./lab.sh atacar A5 && ./lab.sh explicar ultimo   # pasa todo: es SU dominio
./lab.sh atacar A6 && ./lab.sh explicar ultimo
docker compose run --rm toolbox pytest -q        # matriz completa en verde
```

---

## Fase 7: Pulido y documentación

**Objetivo:** que cualquier persona pueda clonar, entender y usar el lab sin ti.

**Qué se construye:**

- `README.md`: qué es, aviso de uso ético, requisitos, inicio rápido en 3 comandos, tabla de escenarios, matriz de resultados, GIF, limitaciones y créditos.
- `docs/`: `teoria.md` (con diagramas Mermaid), `implementacion-produccion.md`, `guion-presentacion.md`, `solucion-de-problemas.md` y `glosario.md`.
- `SECURITY.md` y `CONTRIBUTING.md`.
- `.github/workflows/ci.yml`: build, levantar el compose, pytest, `ruff` y `shellcheck`.
- Revisión final de secretos.
- **Esta guía, sincronizada con el código real.**

**Prompt:**
> Fase 7 de CLAUDE.md. Revisa el repo como si fueras a publicarlo. Escribe el README principal y los documentos de docs/. Crea SECURITY.md, CONTRIBUTING.md y el workflow de CI. Revisa todo el historial y los archivos en busca de secretos o llaves. Por último, actualiza docs/construir-desde-cero.md para que cada comando, archivo y salida esperada coincida exactamente con el código final.

**Verificación (la prueba de fuego):**
```bash
cd /tmp && git clone ~/proyectos/email-auth-lab prueba && cd prueba
docker compose up -d --build && docker compose run --rm toolbox pytest -q
```
✅ Un clon limpio pasa todos los tests sin pasos manuales extra. Esto demuestra que el lab es replicable.

---

## 10. Grabar evidencias para la presentación

Las demos en vivo fallan; ten todo grabado.

- **Terminal:** `asciinema rec escenario-3.cast` dentro de Ubuntu (instálalo con `sudo apt install asciinema`). Convierte a GIF con `agg`.
- **Mailpit:** en Windows usa ScreenToGif; en macOS, `Cmd+Shift+5`.
- Guarda todo en `docs/img/` y enlázalo en cada README de escenario.
- Fuente de la terminal en 20 pt o más, y modo claro, para proyectar.
- **Sin Internet en el evento:** construye el día anterior (`docker compose build`). Para repartir el lab, exporta las imágenes:
  ```bash
  docker save $(docker compose config --images) -o email-auth-lab-imagenes.tar
  # en otra máquina: docker load -i email-auth-lab-imagenes.tar
  ```

---

## 11. Publicar en GitHub

1. **Última revisión:**
   ```bash
   git status                                # sin llaves/, estado/, .env
   git log --all -p | grep -i "PRIVATE KEY"  # no debe imprimir nada
   ```
2. **Crea el repositorio y súbelo:**
   ```bash
   gh repo create email-auth-lab --public --source=. --remote=origin \
     --description "Laboratorio local de SPF, DKIM y DMARC: qué son, cómo se implementan y de qué protegen" --push
   ```
3. En GitHub ve a *Settings → Advanced Security* y activa **Secret Protection** y **Push protection**.
4. En el engrane de *About*, agrega los topics: `email-security`, `spf`, `dkim`, `dmarc`, `phishing`, `bec`, `blue-team`, `docker`, `lab`.
5. **Release:**
   ```bash
   git tag v1.0.0 && git push --tags
   gh release create v1.0.0 --title "v1.0.0" --notes "Primera versión pública del laboratorio"
   ```

> Si alguna vez subes una llave por error: no basta con borrar el commit. Regenera las llaves (`./lab.sh reset --llaves` o borra el volumen) y limpia el historial.

---

## 12. Problemas comunes

| Síntoma | Causa probable | Solución |
|---|---|---|
| Docker Desktop no arranca en Windows | Virtualización apagada o WSL2 sin instalar | Activa VT-x/AMD-V en la BIOS; corre `wsl --install` |
| `docker: command not found` en Ubuntu | Falta la integración WSL | Docker Desktop → *Settings → Resources → WSL Integration* |
| Scripts fallan con `\r: command not found` | Finales de línea CRLF | `git config --global core.autocrlf input`, vuelve a clonar; verifica `.gitattributes` |
| `localhost:8025` no abre | Mailpit solo en la red interna, o puerto ocupado | Revisa que Mailpit esté en `ui-net`; cambia el puerto en `.env` |
| `Authentication-Results` sin SPF/DKIM | Rspamd considera la red como local | Ajusta `local_addrs` (ver CLAUDE.md, sección 3) |
| El cambio de escenario no se nota | Caché DNS o serial SOA sin cambiar | TTL de 5 s; incrementa el serial; `./lab.sh verificar` |
| `dkim=fail` en el correo legítimo | Llave publicada distinta de la que firma | `./lab.sh reset --llaves` regenera llaves y zonas juntas |
| Construcción muy lenta en Windows | Proyecto en `C:\` y no en WSL | Mueve el proyecto a `~/proyectos/` dentro de Ubuntu |
