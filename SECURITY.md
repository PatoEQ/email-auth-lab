# Seguridad

## Propósito y uso aceptable

`email-auth-lab` es un laboratorio **educativo y defensivo**. Muestra cómo se suplanta el remitente de un correo para que las personas de TI y seguridad entiendan y configuren SPF, DKIM y DMARC.

Úsalo solo en tu propia computadora y con los dominios ficticios del laboratorio. **No** lo modifiques para enviar correo a terceros, a dominios reales o a sistemas que no sean tuyos: además de poco ético, suplantar a otras personas u organizaciones puede ser un delito.

## Cómo está contenido

| Medida | Dónde |
|---|---|
| Red `lab-net` con `internal: true`: ningún contenedor que envía correo tiene salida a Internet | `docker-compose.yml` |
| Solo dominios `.test` (RFC 2606) e IPs de documentación (192.0.2.0/24) en los ejemplos | Zonas DNS, `reportes/ejemplos/` |
| Los ataques validan el destino: solo dominios `.test` y solo el host `receptor`; cualquier otro destino aborta | `atacante/ataques/comun.py` |
| Las APIs del atacante y del reenviador solo existen dentro de `lab-net`, solo ejecutan acciones de un catálogo fijo y validan cada parámetro que reciben | `atacante/servidor.py`, `reenviador/servidor.py` |
| Único puerto publicado: la interfaz de Mailpit, en `127.0.0.1` | `docker-compose.yml` (lo comprueba la CI) |
| Sin `docker.sock` dentro de los contenedores | El cambio de escenario usa volúmenes compartidos |
| Llaves DKIM generadas al arrancar, en un volumen fuera del repositorio; el atacante nunca recibe la llave del banco | `init/`, montajes `subpath` |
| Contenedores del atacante y del reenviador sin privilegios (usuario propio) | `atacante/entrypoint.sh`, `reenviador/Dockerfile` |
| Revisión de secretos en todo el historial con gitleaks en cada push | `.github/workflows/ci.yml` |

Las llaves DKIM del laboratorio son reales (RSA de 2048 bits), pero solo valen para dominios `.test`, que no existen en Internet. Para regenerarlas: `docker compose down -v`.

## Reportar una vulnerabilidad

Si encuentras una forma de que el laboratorio:

- envíe correo o tráfico fuera de la red interna,
- acepte destinos que no sean `.test` o el host `receptor`,
- exponga puertos fuera de `127.0.0.1`,
- filtre llaves o secretos al repositorio,

o cualquier otro problema de seguridad, **no abras un issue público**. Repórtalo de forma privada desde la pestaña **Security → Report a vulnerability** del repositorio en GitHub (*private vulnerability reporting*).

Incluye los pasos para reproducirlo, el impacto y, si puedes, una propuesta de solución. Responderemos lo antes posible y te daremos crédito en la corrección, si así lo quieres.

## Versiones con soporte

Solo la última versión de la rama `main`.
