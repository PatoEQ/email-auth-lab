# Solución de problemas

Primero, siempre:

```bash
docker compose ps                 # ¿todo «Up» y «healthy»? (init termina: es normal que no aparezca)
./lab.sh estado                   # salud de cada servicio y registros publicados
./lab.sh verificar                # qué publica el DNS ahora mismo
docker compose logs <servicio>    # receptor, emisor, atacante, dns, init…
```

## Instalación y arranque

| Síntoma | Causa | Solución |
|---|---|---|
| Docker Desktop no arranca en Windows | Virtualización apagada o WSL2 sin instalar | Activa VT-x/AMD-V en la BIOS y corre `wsl --install` |
| `docker: command not found` en Ubuntu (WSL) | Falta la integración con WSL | Docker Desktop → *Settings → Resources → WSL Integration* → activa tu distribución |
| `\r: command not found` o `bad interpreter` al correr `./lab.sh` | El repo se clonó con finales de línea CRLF | `git config --global core.autocrlf input` y vuelve a clonar. El repo fuerza LF con `.gitattributes` |
| `permission denied: ./lab.sh` | El archivo perdió el permiso de ejecución | `chmod +x lab.sh` o `bash lab.sh estado` |
| La construcción es muy lenta en Windows | El repo está en `C:\` (se accede vía `/mnt/c`) | Clónalo dentro de Ubuntu, por ejemplo en `~/proyectos/` |
| `init` termina con `Exited (1)` | Falló la generación de llaves o de zonas | `docker compose logs init`: el mensaje empieza con `[init]` |

## Uso

| Síntoma | Causa | Solución |
|---|---|---|
| http://localhost:8025 no abre | Puerto ocupado por otro programa | Copia `.env.example` a `.env`, cambia `MAILPIT_PUERTO` y corre `docker compose up -d` |
| `Error response from daemon: failed to set up container networking: Address already in use` al usar `./lab.sh` | Ya hay otra toolbox corriendo (tiene IP fija 172.28.0.100), por ejemplo los tests | Espera a que termine; `docker ps` muestra la otra `toolbox` |
| `./lab.sh` usa código viejo después de cambiar `toolbox/` | La imagen de la toolbox no se reconstruyó | `docker compose up -d --build` (la toolbox se construye con `up` aunque no arranque: tiene `scale: 0`) |
| `lab reenviar`: «El reenviador no está levantado» | El servicio es opcional (perfil `extras`) | `docker compose --profile extras up -d --build`, o `COMPOSE_PROFILES=extras` en `.env` |
| `lab atacar A3`: «No hay ningún correo legítimo del director» | A3 necesita un correo legítimo para alterarlo | `./lab.sh enviar legit` y vuelve a intentar |
| `lab explicar ultimo` muestra otro correo y no el ataque | El ataque fue **rechazado** (5xx): nunca llegó a la bandeja | Es lo esperado en `3-reject`; la respuesta SMTP se ve en la salida de `lab atacar` |
| `lab escenario` advierte «el emisor no lo confirmó» | El emisor no aplicó la firma DKIM del escenario en 15 s | `docker compose logs emisor`; si no se recupera, `docker compose restart emisor` |

## Por qué el laboratorio está configurado así (problemas que ya resolvimos)

Lo que sigue explica decisiones que **ya están aplicadas** en el repositorio. Sirve para entender la configuración o para reproducirla en otro entorno.

### Rspamd no verificaba SPF ni DMARC

**Síntoma:** `Authentication-Results: receptor.bancoseguro.test; none`. En los logs del receptor: `skip SPF checks for local networks and authorized users`.

**Causa:** Rspamd trata las IPs privadas (172.28.0.0/24) como "locales" y se salta las verificaciones. Cambiar `local_addrs` no basta: `spf.lua` y `dmarc.lua` consultan `ip:is_local()` (RFC 1918).

**Solución:** `receptor/rspamd/options.inc` define `local_addrs = ["127.0.0.0/8", "::1"]` **y** `check_local = true`.

### El cambio de SPF tardaba 5 minutos en notarse

**Causa:** Rspamd guarda los SPF en caché un mínimo de 5 minutos (`min_cache_ttl = 5min`), aunque el registro tenga TTL de 5 s.

**Solución:** `receptor/rspamd/spf.conf` con `min_cache_ttl = 1s`. Además, `lab escenario` espera un TTL (5 s) cuando cambia alguna zona: dentro de ese plazo, usar el registro anterior de la caché es lo correcto según DNS.

### El correo marcado o rechazado por puntaje, no por DMARC

**Causa:** Rspamd suma puntos (por ejemplo, 4,4 por `spf=fail`) y aplica acciones por umbral (`greylist`, `add header`, `reject`).

**Solución:** `receptor/rspamd/actions.conf` desactiva las acciones por puntaje. Solo la política DMARC (`dmarc.conf`) marca o rechaza. Es una decisión **didáctica**, no para producción.

### Un registro DKIM aparecía dos veces en el DNS

**Causa:** un comentario de la plantilla de zona contenía el marcador `{{REGISTROS_ESCENARIO}}` y también se reemplazaba.

**Solución:** se quitó el marcador del comentario. `init/renderizar_zonas.py` ahora falla si un comentario contiene un marcador.

### CoreDNS no servía una zona nueva

**Causa:** CoreDNS leía el `Corefile` solo al arrancar, y Docker no refleja el reemplazo de un **archivo** montado individualmente (por ejemplo, después de un `git pull`).

**Solución:** se monta la carpeta `dns/` completa y el Corefile usa el plugin `reload`. Si aun así hiciera falta: `docker compose restart dns`.

## Volver a empezar de cero

```bash
docker compose --profile extras down -v   # borra contenedores Y volúmenes (llaves DKIM, estado, zonas)
docker compose up -d --build              # init genera llaves nuevas y renderiza las zonas
```

`down -v` también es la forma de **regenerar las llaves DKIM**. Sin `-v`, las llaves y el escenario activo se conservan entre reinicios.
