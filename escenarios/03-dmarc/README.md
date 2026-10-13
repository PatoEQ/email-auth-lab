# Escenario 3: DMARC (none → quarantine → reject)

## Objetivo

Cerrar los dos huecos que dejaron SPF y DKIM:

1. **Alineación.** No basta con que SPF o DKIM pasen: tienen que pasar para **el mismo dominio que ve el empleado** en el `From:`.
2. **Política.** El dueño del dominio le dice al receptor qué hacer si la verificación falla: solo observar (`none`), marcar (`quarantine`) o rechazar (`reject`).

Recorremos las tres políticas en el mismo orden que se sigue en producción y vemos cómo A1–A4 pasan de "entregados" a "marcados" y luego a "rechazados", mientras el correo legítimo sigue llegando.

## Qué se configura

**DNS de `bancoseguro.test`:** se mantienen SPF y DKIM y se agrega un registro en `_dmarc`.

```
_dmarc  IN TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reportes@bancoseguro.test"
```

| Escenario | Registro DMARC |
|---|---|
| `3-none` | `v=DMARC1; p=none; rua=mailto:dmarc-reportes@bancoseguro.test` |
| `3-quarantine` | igual, con `p=quarantine` |
| `3-reject` | igual, con `p=reject` |

| Etiqueta | Significado |
|---|---|
| `v=DMARC1` | Esto es un registro DMARC |
| `p=` | Política para los correos que fallan: `none`, `quarantine` o `reject` |
| `rua=` | Dónde enviar los **reportes agregados** diarios (quién envió en nombre del dominio y con qué resultado) |
| `adkim=` / `aspf=` | Alineación `r` (relajada, por defecto: vale un subdominio) o `s` (estricta: el dominio exacto). Aquí usamos la relajada |

**Cómo decide el receptor (DMARC pasa si se cumple al menos una de estas dos condiciones):**

- **SPF pasa** y el dominio del sobre (`MAIL FROM`) **coincide** con el del `From:`, o
- **DKIM pasa** y el `d=` de la firma **coincide** con el del `From:`.

**Receptor (Rspamd):** la configuración sigue la [documentación oficial del módulo DMARC](https://docs.rspamd.com/modules/dmarc/). La contrastamos con el código de la versión instalada (3.12.1): `dmarc.lua` aplica `settings.actions[disposición]`.

```
# receptor/rspamd/dmarc.conf
actions {
  reject = "reject";               # p=reject     → respuesta SMTP 5xx
  quarantine = "rewrite subject";  # p=quarantine → se entrega con el asunto marcado
}

# receptor/rspamd/actions.conf
subject = "[CUARENTENA] %s";
```

Dos decisiones propias del laboratorio:

- **Desactivamos las acciones por puntaje antispam** (`reject`, `add_header`, `greylist` y `rewrite_subject` en `null`). Así, lo único que marca o rechaza es la política DMARC, y se ve con claridad su efecto. En producción, el puntaje antispam convive con DMARC.
- **La respuesta de rechazo dice el motivo:** `554 5.7.1 Rechazado por la politica DMARC (p=reject) del dominio del remitente`. Va sin tildes porque SMTP es ASCII.

## Pasos

```bash
./lab.sh reset
./lab.sh escenario 3-none
./lab.sh enviar legit && ./lab.sh atacar --todos     # todo llega; los ataques con dmarc=fail
./lab.sh reportes                                     # qué vería el banco en los reportes rua

./lab.sh escenario 3-quarantine
./lab.sh enviar legit && ./lab.sh atacar --todos     # los ataques llegan con [CUARENTENA]

./lab.sh escenario 3-reject
./lab.sh enviar legit && ./lab.sh atacar --todos     # los ataques se rechazan con 554
```

En PowerShell, usa `.\lab.ps1` en lugar de `./lab.sh`.

En http://localhost:8025 se ve la evolución: primero llegan todos los correos, después los ataques llegan marcados y al final solo llega el correo legítimo.

## Resultado esperado

| Envío | 3-none | 3-quarantine | 3-reject |
|---|---|---|---|
| Legítimo | Entregado · `dmarc=pass` | Entregado · `dmarc=pass` | Entregado · `dmarc=pass` |
| A1 · Suplantación directa | Entregado · `dmarc=fail` | Entregado **con `[CUARENTENA]`** | **Rechazado (554)** |
| A2 · Sobre del atacante | Entregado · `dmarc=fail` | Entregado **con `[CUARENTENA]`** | **Rechazado (554)** |
| A3 · Legítimo alterado | Entregado · `dmarc=fail` | Entregado **con `[CUARENTENA]`** | **Rechazado (554)** |
| A4 · Firma de otro dominio | Entregado · `dmarc=fail` | Entregado **con `[CUARENTENA]`** | **Rechazado (554)** |

`Authentication-Results` explica por qué falló cada uno. Estos son los motivos reales del laboratorio:

| Envío | `reason=` de Rspamd | Qué significa |
|---|---|---|
| A1 | `No valid SPF, No valid DKIM` | La IP no está autorizada y no hay firma |
| A2 | `SPF not aligned (relaxed), No valid DKIM` | SPF pasa, pero para `atacante.test` |
| A3 | `No valid SPF` | La firma del banco ya no es válida porque el cuerpo cambió |
| A4 | `SPF not aligned (relaxed), DKIM not aligned (relaxed)` | SPF y DKIM pasan, pero ninguno es de `bancoseguro.test` |

Y en `3-reject`:

```
A1 · Suplantación directa
  Respuesta SMTP: 554 5.7.1 Rechazado por la politica DMARC (p=reject) del dominio del remitente
  RECHAZADO: el receptor lo bloqueó en la conversación SMTP. El correo nunca llegó a la bandeja del empleado.
```

### Los reportes agregados (`lab reportes`)

Con `rua=`, cada proveedor que recibe correo "de" `bancoseguro.test` envía a diario un XML con un resumen: desde qué IPs llegó, cuántos correos y si pasaron SPF, DKIM y DMARC. El formato está definido en el RFC 7489, apéndice C.

En el laboratorio no se envían reportes reales, porque Rspamd necesitaría Redis y un correo de salida. En su lugar, `reportes/ejemplos/` tiene un reporte **100 % ficticio**: dominios `.test` e IPs del rango de documentación 192.0.2.0/24. `./lab.sh reportes` lo muestra interpretado:

| # | IP | Correos | Diagnóstico |
|---|---|---|---|
| 1 | 192.0.2.10 | 1250 | **Legítimo:** el servidor del banco, alineado |
| 2 | 192.0.2.140 | 412 | **Servicio sin alinear:** una plataforma de boletines que firma como `envios-masivos.test` |
| 3 | 192.0.2.25 | 340 | **Reenvío:** una lista de correo. SPF falla, pero DKIM alineado sobrevive |
| 4 | 192.0.2.77 | 89 | **Posible suplantación:** nada autentica ese correo |

Resumen: 1590 de 2091 correos pasan DMARC. Si el banco pasara hoy a `p=reject`, perdería también los 412 boletines legítimos de la fila 2. **Por eso no se salta directamente a `reject`.**

## La ruta en producción: none → quarantine → reject

Cada etapa dura semanas y solo se avanza cuando los reportes lo justifican.

1. **Inventario y bases.** Hay que listar todo lo que envía correo con el dominio: servidores propios, CRM, facturación, boletines, mesa de ayuda, alertas… Luego, publicar SPF con esas fuentes y activar DKIM con el **dominio propio** (`d=bancoseguro.test`) en cada servicio que lo permita.
2. **`p=none` con `rua=` (observación, de 2 a 6 semanas o más).** No cambia la entrega de ningún correo. Se reciben y se analizan los reportes, idealmente con una herramienta que los agregue. Para cada fuente que falle hay que preguntar: ¿es nuestra? Si lo es, se alinea (DKIM con nuestro dominio, o un sobre con un subdominio propio). Si no lo es, es justo lo que queremos bloquear. Se avanza cuando las fuentes legítimas pasan DMARC de forma estable.
3. **`p=quarantine` de forma gradual.** Se puede usar `pct=` (por ejemplo `p=quarantine; pct=10`, luego 25, 50 y 100) para aplicar la política solo a una parte de los correos que fallan. Sirve para detectar con poco riesgo alguna fuente olvidada. Se siguen revisando los reportes y las quejas de "no me llegó tal correo".
4. **`p=reject`.** Primero con `pct=` bajo y luego al 100 %. Los correos que suplantan el dominio se rechazan en SMTP.
5. **Después:**
   - mantener los reportes vigilados, porque cada servicio nuevo que contrate el área de Marketing es una fuente nueva;
   - publicar `sp=reject` para los subdominios;
   - proteger con `v=spf1 -all` y `p=reject` los dominios que **no envían** correo (escenario 5);
   - rotar las llaves DKIM.

Errores típicos:

- pasar directo a `p=reject` sin haber leído los reportes;
- quedarse para siempre en `p=none`, que da visibilidad pero **ninguna protección**;
- olvidar los subdominios y los dominios que no envían correo.

## Qué aprendimos y qué sigue sin cubrirse

- DMARC une SPF y DKIM con el dominio que **ve** el usuario (alineación), y le da al dueño del dominio la decisión (política).
- Con `p=reject`, A1–A4 se bloquean. A4 lo demuestra bien: tiene `spf=pass` y `dkim=pass`, pero ninguno es de `bancoseguro.test`.
- `p=none` no protege nada. Es una etapa para **observar** antes de bloquear, no un destino.
- Los reportes `rua` son la herramienta para avanzar sin perder correo legítimo.
- Sigue sin cubrirse:
  - **dominios parecidos** (`bancos3guro.test`), que tienen su propio DMARC impecable (escenario 4);
  - **suplantación del nombre visible** ("Director General" con una dirección cualquiera) (escenario 4);
  - el **reenvío**, que rompe SPF; DKIM lo compensa si el reenviador no altera el correo (escenario 5).

## Preguntas para la audiencia

1. ¿Qué política DMARC publica hoy su dominio principal? ¿Y los dominios que no envían correo?
2. ¿Por qué A4 falla DMARC si SPF y DKIM pasan?
3. Si mañana publicaran `p=reject`, ¿qué servicio de su organización dejaría de entregar correo?
4. ¿Quién revisa los reportes `rua` en su organización y cada cuánto?
