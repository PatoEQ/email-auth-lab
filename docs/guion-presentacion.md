# Guion de presentación (45–60 minutos)

Charla para personas de TI y seguridad que no son expertas en correo. La idea central: **cada defensa resuelve una parte del problema y deja otra al descubierto**. El público lo ve en vivo, en una terminal y en una bandeja de correo.

## Preparación (el día anterior)

```bash
docker compose --profile extras up -d --build --wait   # construye todo con Internet
./lab.sh estado                                         # todo en ✓ ok, reenviador incluido
docker compose run --rm toolbox pytest -q               # la tabla de verdad completa en verde
```

- **Sin Internet en el evento:** el laboratorio no la necesita una vez construido. Para llevarlo a otra máquina:
  ```bash
  docker save $(docker compose --profile extras config --images) -o email-auth-lab-imagenes.tar
  # en la otra máquina: docker load -i email-auth-lab-imagenes.tar
  ```
- **Pantalla:** terminal con fuente de 20 pt o más y tema claro; navegador con http://localhost:8025 en otra pestaña o en la otra mitad de la pantalla.
- **Plan B:** las capturas de `docs/img/` muestran la salida real de los comandos clave. Puedes regenerarlas con `docker compose run --rm -v ./docs/img:/salida toolbox python -m lab.capturas /salida`.
- Justo antes de empezar: `./lab.sh reset`.

## Guion

### 1. La historia (5 min)

> "Viernes, 17:40. Llega un correo del director general: hay que transferir 48.500 dólares hoy, es confidencial, no lo comentes. ¿Lo harían?"

- Presenta el fraude del CEO (BEC) y a *Banco Seguro*.
- Muestra el diagrama de arquitectura del [README](../README.md#arquitectura): todo es local, la red no tiene Internet y los dominios son `.test`.

### 2. Escenario 0: sin protección (7 min)

```bash
./lab.sh escenario 0
./lab.sh enviar legit
./lab.sh atacar A1
```

- En Mailpit, los dos correos son "del director". **Pregunta:** ¿cuál es el real?
- Abre *Headers* y busca `Authentication-Results`: `spf=none`, `dkim=none`, `dmarc=none`.
- **Mensaje:** SMTP no verifica al remitente. `none` significa "no hay nada contra qué comparar".

### 3. Escenario 1: SPF (8 min)

```bash
./lab.sh escenario 1          # se ve el registro TXT agregado
./lab.sh atacar A1            # spf=fail… pero llega
./lab.sh atacar A2            # spf=pass
./lab.sh explicar ultimo
```

- Explica la diferencia entre el sobre y el `From:` con A2: SPF pasa **para atacante.test**.
- **Pregunta:** si su filtro dice `spf=pass`, ¿qué pueden afirmar?

### 4. Escenario 2: DKIM (8 min)

```bash
./lab.sh escenario 2
./lab.sh enviar legit
./lab.sh atacar A3            # el correo real con la cuenta cambiada
./lab.sh explicar ultimo      # body hash did not verify
./lab.sh atacar A4
```

- Muestra en Mailpit la cabecera `DKIM-Signature` y explica `d=`, `s=`, `bh=` y `b=`.
- A3: el mismo correo, con la misma firma y otra cuenta bancaria. DKIM lo detecta… y **lo entrega igual**.
- A4: una firma válida de `atacante.test`.

### 5. Escenario 3: DMARC (10 min)

```bash
./lab.sh escenario 3-none        && ./lab.sh atacar --todos
./lab.sh reportes
./lab.sh escenario 3-quarantine  && ./lab.sh atacar --todos
./lab.sh escenario 3-reject      && ./lab.sh enviar legit && ./lab.sh atacar --todos
```

- `none`: todo llega, pero ahora hay **reportes**. En la fila 2 del reporte aparece el servicio de boletines legítimo que se perdería si se pasara directo a `reject`.
- `quarantine`: `[CUARENTENA]` en la bandeja.
- `reject`: `554 … DMARC`. A1–A4 nunca llegan; el legítimo, sí. Muestra la tabla de verdad del README.
- **Mensaje:** el camino en producción es none → quarantine → reject, guiado por los reportes.

### 6. Escenario 4: los límites (7 min)

```bash
./lab.sh escenario 4
./lab.sh atacar A5 && ./lab.sh explicar ultimo
./lab.sh atacar A6 && ./lab.sh explicar ultimo
```

- Pide al público que lea rápido `bancoseguro.test` y `bancos3guro.test`.
- En A6, muestra cómo se ve "Director General" en la lista de Mailpit.
- **Mensaje:** la autenticación protege el **dominio exacto**, no la marca ni la atención de las personas. Hacen falta procesos: confirmar por otro canal.

### 7. Opcional: escenario 5 (5 min)

```bash
./lab.sh escenario 5
./lab.sh atacar N1                 # dominio que no envía: rechazado
./lab.sh enviar legit
./lab.sh reenviar                  # SPF falla, DKIM rescata DMARC
./lab.sh reenviar --lista          # la lista modifica el correo: rechazado
```

### 8. Cierre (5 min)

1. Publiquen SPF y **firmen con DKIM con su propio dominio** todo lo que envían.
2. DMARC con `rua`, y avancen de `none` a `reject` leyendo los reportes.
3. Protejan los dominios que no envían correo.
4. Dominios parecidos y nombres visibles: etiquetas de remitente externo y **procesos** de verificación.

Invita a clonar el repositorio y a repetir el laboratorio.

## Preguntas frecuentes del público

| Pregunta | Respuesta corta |
|---|---|
| ¿`p=reject` puede bloquear correo legítimo? | Sí, si una fuente legítima no está alineada. Por eso se pasa antes por `p=none` y se leen los reportes |
| ¿Por qué no basta con SPF? | Porque no mira el `From:` (A2) y se rompe con el reenvío |
| ¿Y si me roban la cuenta del director? | El correo sale del servidor legítimo y pasa todo: hacen falta MFA, alertas y procesos |
| ¿Qué es ARC? | Un sello de los intermediarios (listas) que dice qué resultados vieron antes de modificar el correo |
| ¿Cuánto cuesta implementar todo esto? | Los registros son gratis; el trabajo está en el inventario y en leer los reportes |

## Si algo falla en vivo

| Problema | Acción |
|---|---|
| Un comando tarda o falla | `./lab.sh estado`; si un servicio está en ✗, `docker compose restart <servicio>` |
| `Address already in use` al correr `./lab.sh` | Hay otra toolbox en marcha (por ejemplo, los tests): espera a que termine |
| El cambio de escenario "no se nota" | `./lab.sh verificar` muestra lo que publica el DNS ahora |
| Nada funciona | Pasa a las capturas de `docs/img/` y a la tabla de verdad del README |

Más detalles en [solucion-de-problemas.md](solucion-de-problemas.md).
