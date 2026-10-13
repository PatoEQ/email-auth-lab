# Guía de uso

Cómo instalar lo necesario, descargar el laboratorio y recorrer los escenarios **tal como está en el repositorio**, sin construir nada. Si te interesa cómo se construyó, fase por fase, mira [construir-desde-cero.md](construir-desde-cero.md).

## Índice

1. [Qué necesitas](#1-qué-necesitas)
2. [Instalar los requisitos](#2-instalar-los-requisitos)
3. [Descargar el laboratorio](#3-descargar-el-laboratorio)
4. [Primer arranque](#4-primer-arranque)
5. [Recorrer los escenarios](#5-recorrer-los-escenarios)
6. [Uso diario](#6-uso-diario)
7. [Desinstalar](#7-desinstalar)
8. [Problemas comunes](#8-problemas-comunes)

---

## 1. Qué necesitas

| Recurso | Mínimo | Recomendado |
|---|---|---|
| Sistema | Windows 10/11 (con WSL2), macOS o Linux de 64 bits | — |
| RAM | 8 GB | 16 GB |
| Disco libre | 3 GB | 10 GB |
| CPU | 64 bits con virtualización activada | 4 núcleos o más |
| Internet | Para instalar y para el primer arranque | Después, el laboratorio funciona sin conexión |

Solo hacen falta **dos programas**:

- **Docker con Compose v2:** corre los contenedores del laboratorio. En Windows y macOS es Docker Desktop; en Linux, Docker Engine.
- **Git:** para descargar el repositorio y actualizarlo. Si no lo quieres instalar, puedes [descargar el ZIP](#opción-b-descargar-el-zip).

Todo lo demás (Postfix, Rspamd, CoreDNS, Python, `dig`, `swaks`…) viene **dentro** de los contenedores. No tienes que instalarlo.

> El laboratorio está probado en Linux y en Windows con WSL2. En macOS (Intel o Apple Silicon) debería funcionar igual, porque todas las imágenes son multiarquitectura, pero no lo hemos probado.

---

## 2. Instalar los requisitos

### Windows 10/11 (todo dentro de WSL)

En Windows, el laboratorio se usa **dentro de Ubuntu (WSL2)**, no desde PowerShell ni desde `C:\`. Es mucho más rápido y evita problemas de finales de línea.

1. **Actualiza Windows** por completo y reinicia.
2. **Comprueba la virtualización.** En el Administrador de tareas, ve a *Rendimiento → CPU* y busca "Virtualización: Habilitado". Si dice deshabilitado, entra a la BIOS y activa Intel VT-x o AMD-V/SVM.
3. **Instala WSL2 con Ubuntu.** En PowerShell **como administrador**:
   ```powershell
   wsl --install
   ```
   Reinicia. Al abrir **Ubuntu** desde el menú Inicio por primera vez, crea tu usuario y contraseña de Linux.
4. **Instala Docker Desktop** desde https://www.docker.com/products/docker-desktop/ con la opción **WSL 2** marcada. Ábrelo, ve a *Settings → Resources → WSL Integration* y activa tu distribución Ubuntu.
5. **Abre Ubuntu** y comprueba Docker:
   ```bash
   docker run --rm hello-world
   docker compose version
   ```
   ✅ Debes ver "Hello from Docker!" y `Docker Compose version v2.…`.
6. **Instala Git en Ubuntu** (casi siempre ya viene) y evita los finales de línea de Windows:
   ```bash
   sudo apt update && sudo apt install -y git
   git config --global core.autocrlf input
   ```

A partir de aquí, **todos los comandos de esta guía se escriben en la terminal de Ubuntu.**

### macOS

1. Instala **Docker Desktop** desde https://www.docker.com/products/docker-desktop/ (elige Apple Silicon o Intel según tu equipo) y ábrelo.
2. Instala **Git** con `xcode-select --install` (o con [Homebrew](https://brew.sh): `brew install git`).
3. En la Terminal:
   ```bash
   docker run --rm hello-world && docker compose version && git --version
   ```

### Linux (Ubuntu/Debian)

1. Instala **Docker Engine** y el plugin **Compose** siguiendo https://docs.docker.com/engine/install/.
2. Para usar Docker sin `sudo`, agrega tu usuario al grupo `docker` y vuelve a iniciar sesión:
   ```bash
   sudo usermod -aG docker $USER
   ```
3. Instala Git: `sudo apt install -y git`.
4. Comprueba:
   ```bash
   docker run --rm hello-world && docker compose version && git --version
   ```

### Comprobación final

```bash
docker compose version && git --version
```
✅ Los dos comandos responden con una versión (Compose debe ser **v2**).

---

## 3. Descargar el laboratorio

### Opción A: con Git (recomendada)

```bash
mkdir -p ~/proyectos && cd ~/proyectos
git clone https://github.com/PatoEQ/email-auth-lab.git
cd email-auth-lab
```

Con Git, después puedes actualizar con un solo comando ([sección 6](#actualizar-a-la-última-versión)).

### Opción B: descargar el ZIP

Hazlo **dentro de Ubuntu/WSL** (o en la terminal de macOS o Linux), no con el Explorador de Windows: así se conservan los permisos y los finales de línea.

```bash
sudo apt install -y curl unzip            # en macOS ya vienen instalados
mkdir -p ~/proyectos && cd ~/proyectos
curl -L -o email-auth-lab.zip https://github.com/PatoEQ/email-auth-lab/archive/refs/heads/main.zip
unzip email-auth-lab.zip
cd email-auth-lab-main
```

---

## 4. Primer arranque

Desde la carpeta del laboratorio:

```bash
docker compose up -d --build
```

La primera vez descarga y construye las imágenes: tarda **entre 3 y 10 minutos**, según tu conexión. Mientras tanto:

- `init` genera las llaves DKIM (RSA de 2048 bits) y prepara las zonas DNS. Termina solo: es normal que después aparezca como `Exited (0)`.
- Se levantan `dns`, `emisor`, `receptor`, `mailpit` y `atacante` en una red **sin salida a Internet**.

Comprueba que todo responde:

```bash
./lab.sh estado
```

✅ Debes ver:

```
Escenario activo: 0 · Sin protección  (serial 2026101441, desde 2026-10-13T19:25:55+00:00)
Servicios
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Servicio   ┃ Función                         ┃ Estado    ┃ Detalle                                              ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ dns        │ Servidor DNS (CoreDNS)          │ ✓ ok      │ sirve bancoseguro.test (serial 2026101441)           │
│ emisor     │ Servidor de salida del banco    │ ✓ ok      │ acepta conexiones SMTP; firma DKIM desactivada       │
│ receptor   │ MX del banco (Postfix + Rspamd) │ ✓ ok      │ acepta conexiones SMTP                               │
│ mailpit    │ Bandeja web                     │ ✓ ok      │ 0 correos en la bandeja                              │
│ atacante   │ Atacante                        │ ✓ ok      │ listo para lanzar ataques                            │
│ reenviador │ Reenvío / lista (opcional)      │ – apagado │ perfil extras: docker compose --profile extras up -d │
└────────────┴─────────────────────────────────┴───────────┴──────────────────────────────────────────────────────┘
…
Todo listo. El laboratorio responde y puede usarse.
```

El `reenviador` aparece como "apagado": es opcional y solo se usa en el escenario 5.

Por último, abre la **bandeja del empleado** en el navegador: **http://localhost:8025**. Ahí vas a ver llegar (o no) los correos de cada escenario.

> **¿Qué es `./lab.sh`?** Es la puerta de entrada al laboratorio: ejecuta la CLI `lab` dentro del contenedor `toolbox`, en la red aislada. En PowerShell existe `.\lab.ps1`, con los mismos comandos, pero en Windows lo recomendado es usar `./lab.sh` desde Ubuntu. Para ver todos los comandos: `./lab.sh --help`.

---

## 5. Recorrer los escenarios

La historia: un atacante se hace pasar por el director de *Banco Seguro* para pedir una transferencia urgente. En cada escenario el banco agrega una defensa, y tú repites los mismos ataques para ver qué cambia.

Haz los escenarios **en orden**: cada uno se apoya en el anterior. Cada README explica qué se configura, qué esperar y qué preguntas hacerse.

| # | Escenario | Comandos principales | Guía |
|---|---|---|---|
| 0 | Sin protección | `./lab.sh escenario 0` · `./lab.sh enviar legit` · `./lab.sh atacar A1` | [README 00](../escenarios/00-sin-proteccion/README.md) |
| 1 | SPF | `./lab.sh escenario 1` · `./lab.sh atacar A1 A2` · `./lab.sh verificar` | [README 01](../escenarios/01-spf/README.md) |
| 2 | DKIM | `./lab.sh escenario 2` · `./lab.sh enviar legit` · `./lab.sh atacar A3 A4` | [README 02](../escenarios/02-dkim/README.md) |
| 3 | DMARC | `./lab.sh escenario 3-none`, luego `3-quarantine` y `3-reject` · `./lab.sh atacar --todos` · `./lab.sh reportes` | [README 03](../escenarios/03-dmarc/README.md) |
| 4 | Límites | `./lab.sh escenario 4` · `./lab.sh atacar A5 A6` · `./lab.sh explicar ultimo` | [README 04](../escenarios/04-limites/README.md) |
| 5 | Extras (opcional) | `./lab.sh escenario 5` · `./lab.sh atacar N1` · `./lab.sh reenviar` | [README 05](../escenarios/05-extras/README.md) |

Tres comandos que te van a servir en todos los escenarios:

- **`./lab.sh explicar ultimo`** traduce al español los resultados de SPF, DKIM y DMARC del último correo de la bandeja.
- **`./lab.sh verificar`** muestra qué registros publica el DNS en este momento y si su sintaxis es correcta.
- **`./lab.sh reset`** vacía la bandeja y vuelve al escenario 0, para empezar otra vez.

En Mailpit, abre cualquier correo y mira la pestaña **Headers**. La cabecera `Authentication-Results` es la que agrega el receptor con sus verificaciones.

> **Nada sale de tu computadora.** Los dominios son ficticios (`.test`), la red de los contenedores no tiene Internet y los ataques se niegan a enviar a cualquier otro destino. Ver [SECURITY.md](../SECURITY.md).

---

## 6. Uso diario

### Apagar y encender

```bash
docker compose down        # apaga y borra los contenedores; conserva llaves, escenario y estado
docker compose up -d       # lo vuelve a encender en segundos, en el mismo escenario
```

Docker Desktop también puede quedar cerrado: al abrirlo de nuevo, los contenedores vuelven a arrancar solos (`restart: unless-stopped`).

### Volver a empezar de cero

```bash
docker compose --profile extras down -v    # -v borra también los volúmenes: llaves DKIM, estado y zonas
docker compose up -d
```

`init` genera llaves nuevas al arrancar. Para solo vaciar la bandeja y volver al escenario 0, basta con `./lab.sh reset`.

### Activar el escenario 5 (reenviador)

```bash
docker compose --profile extras up -d --build
```

Para que el reenviador arranque siempre, copia `.env.example` a `.env` y descomenta la línea `COMPOSE_PROFILES=extras`.

### Cambiar el puerto de Mailpit

Si el 8025 está ocupado:

```bash
cp .env.example .env       # y edita MAILPIT_PUERTO, por ejemplo MAILPIT_PUERTO=9025
docker compose up -d
```

La bandeja queda en http://localhost:9025 (siempre solo en `127.0.0.1`, no se expone a tu red).

### Actualizar a la última versión

```bash
git pull
docker compose up -d --build
```

Si descargaste el ZIP, descarga uno nuevo; tus llaves y tu estado se conservan, porque viven en volúmenes de Docker y no en la carpeta.

### Correr los tests

Para comprobar que todo el laboratorio se comporta como dice la tabla de verdad:

```bash
docker compose --profile extras up -d --build --wait
docker compose run --rm toolbox pytest -q
```

✅ `154 passed`, en unos 9 minutos. Mientras los tests corren, no uses `./lab.sh`: los dos usan la misma toolbox.

---

## 7. Desinstalar

Desde la carpeta del laboratorio:

```bash
docker compose --profile extras down -v --rmi all    # contenedores, volúmenes, red e imágenes
cd .. && rm -rf email-auth-lab                        # o email-auth-lab-main si usaste el ZIP
```

Docker Desktop, WSL y Git se desinstalan como cualquier programa, si ya no los necesitas.

---

## 8. Problemas comunes

| Síntoma | Causa | Solución |
|---|---|---|
| `docker: command not found` en Ubuntu (WSL) | Falta la integración con WSL | Docker Desktop → *Settings → Resources → WSL Integration* → activa Ubuntu |
| `permission denied while trying to connect to the Docker daemon` (Linux) | Tu usuario no está en el grupo `docker` | `sudo usermod -aG docker $USER` y vuelve a iniciar sesión |
| `\r: command not found` al correr `./lab.sh` | Se descargó con finales de línea de Windows | `git config --global core.autocrlf input` y vuelve a clonar dentro de Ubuntu |
| `permission denied: ./lab.sh` | Se perdió el permiso de ejecución (por ejemplo, al extraer el ZIP con el Explorador) | `chmod +x lab.sh`, o usa `bash lab.sh …` |
| http://localhost:8025 no abre | Puerto ocupado, o el laboratorio no está levantado | `docker compose ps`; si es el puerto, [cámbialo](#cambiar-el-puerto-de-mailpit) |
| `Address already in use` al correr `./lab.sh` | Hay otra toolbox en marcha (por ejemplo, los tests) | Espera a que termine |
| Todo va muy lento en Windows | El laboratorio está en `C:\` (`/mnt/c/…`) | Clónalo dentro de Ubuntu, en `~/proyectos/` |
| `./lab.sh estado` muestra un servicio con ✗ | El contenedor no arrancó o se detuvo | `docker compose logs <servicio>` y `docker compose up -d` |

La lista completa está en [solucion-de-problemas.md](solucion-de-problemas.md).
