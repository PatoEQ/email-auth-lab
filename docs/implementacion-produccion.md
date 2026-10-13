# Implementación en producción

Cómo llevar lo que muestra el laboratorio a un dominio real, sin perder correo legítimo por el camino. Es una guía genérica: los pasos exactos de cada proveedor (Microsoft 365, Google Workspace, plataformas de envío masivo, etc.) están en su documentación oficial.

> En el laboratorio, Rspamd tiene ajustes **didácticos** que **no** deben copiarse: las acciones por puntaje antispam están desactivadas, para que solo decida DMARC, y la caché de SPF se reduce a 5 s. En producción, el filtro antispam y DMARC trabajan juntos.

## Resumen del plan

| Etapa | Duración típica | Qué se hace | Cuándo avanzar |
|---|---|---|---|
| 0. Inventario | 1–2 semanas | Listar todo lo que envía correo con tus dominios | Cuando cada fuente tiene un responsable |
| 1. SPF y DKIM | 2–4 semanas | Autorizar las fuentes y firmar con **tu** dominio | Cuando cada fuente legítima sale alineada |
| 2. DMARC `p=none` | 4–8 semanas | Recibir y analizar reportes `rua` | Cuando ≥ 98–99 % del correo legítimo pasa DMARC de forma estable |
| 3. `p=quarantine` | 2–6 semanas | Subir `pct=` de forma gradual | Sin quejas de correo legítimo marcado |
| 4. `p=reject` | — | Primero con `pct=` bajo, luego al 100 % | Estado final: mantener y vigilar |

## 0. Inventario

Antes de publicar nada, responde: **¿qué envía correo con `From: …@tudominio`?**

- Servidores propios y la plataforma de correo corporativo.
- Servicios en la nube: CRM, facturación, mesa de ayuda, RR. HH., boletines, encuestas, alertas de monitoreo, impresoras multifunción.
- Proveedores que envían "en nombre de" la organización (agencias, call centers).
- Dominios y subdominios: también los de marca, los antiguos y los que **no** envían correo.

Para cada fuente, anota: responsable, IPs o mecanismo `include:`, si puede firmar DKIM con tu dominio y qué dominio usa en el sobre.

## 1. SPF

```
tudominio.example.  TXT  "v=spf1 include:_spf.proveedor-correo.example include:envios.crm.example -all"
```

- **Un solo registro SPF por nombre.** Dos registros dan `permerror`.
- **Máximo 10 consultas DNS** (`include`, `a`, `mx`, `exists`, `redirect`). Cada `include:` cuenta, y los suyos también. Si te pasas, consolida proveedores o usa subdominios por servicio (`boletines.tudominio.example` con su propio SPF).
- Empieza con `~all` si el inventario no es confiable y pasa a `-all` cuando los reportes DMARC lo confirmen. Con DMARC en `p=reject`, `~all` y `-all` terminan en lo mismo para DMARC, pero `-all` es más claro.
- Evita `ptr` (obsoleto) y `+all` (autoriza a todo Internet).
- Verifica con `dig TXT tudominio.example`. En el laboratorio, `./lab.sh verificar` hace estas mismas comprobaciones.

## 2. DKIM

- **Firma con tu dominio** (`d=tudominio.example` o un subdominio tuyo) en **todas** las fuentes que lo permitan. Es lo que mantiene DMARC en pie cuando SPF falla por un reenvío ([escenario 5](../escenarios/05-extras/README.md)).
- Llaves **RSA de 2048 bits** como mínimo. Algunos paneles DNS no aceptan TXT largos: el valor se divide en cadenas de 255 caracteres, como hace `init` en el laboratorio.
- **Un selector por fuente y por período** (`s2026`, `crm2026`…), para poder rotar o revocar uno sin tocar los demás.
- **Rotación:** publica el selector nuevo, cambia la firma, espera a que expire el TTL más los correos en tránsito y, al final, revoca el viejo con `p=` vacío.
- Las llaves privadas viven en el servidor que firma o en el proveedor; **nunca** en un repositorio.
- Firma, además de las básicas, las cabeceras que importan: `From` (sobrefirmado), `To`, `Subject`, `Date`, `Message-ID` y las de MIME.

## 3. DMARC

### Etapa de observación

```
_dmarc.tudominio.example.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@tudominio.example; fo=1"
```

- `rua=` es lo más importante de esta etapa. Llegan muchos XML por día: usa una herramienta o un servicio que los agregue. Si la dirección `rua` es de **otro** dominio, ese dominio debe autorizarlo con un registro `tudominio.example._report._dmarc.otro.example`.
- Revisa cada fuente que falle:
  - **Es tuya y no está alineada:** configura DKIM con tu dominio o usa un sobre en un subdominio tuyo.
  - **Es un reenvío:** si DKIM está alineado, DMARC pasa; no hay que hacer nada.
  - **No la reconoces:** es suplantación, justo lo que DMARC va a bloquear.

### Endurecer

```
"v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@tudominio.example"
"v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:dmarc@tudominio.example"
```

- Sube `pct=` por etapas (10 → 25 → 50 → 100) y sigue leyendo los reportes.
- `sp=` define la política de los subdominios. Sin `sp=`, heredan `p=`.
- No te quedes en `p=none`: da visibilidad pero **ninguna protección**.

## 4. Dominios que no envían correo

Cada dominio registrado puede ser suplantado. Para los que no envían correo:

```
noenvia.example.         TXT  "v=spf1 -all"
_dmarc.noenvia.example.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@tudominio.example"
noenvia.example.         MX   0 .                        ; MX nulo (RFC 7505): no recibe correo
*._domainkey.noenvia.example. TXT "v=DKIM1; p="          ; opcional: ninguna llave válida
```

## 5. Del lado del que recibe

Publicar DMARC protege **tu dominio** cuando otros reciben correo de él. Para proteger a **tus usuarios** del correo que **reciben**, tu servidor o filtro de entrada tiene que:

- Verificar SPF, DKIM y DMARC, y **aplicar** la política del remitente (`quarantine` y `reject`), como hace el receptor del laboratorio.
- No eximir de las verificaciones a tus propias redes por error. Es el mismo problema que tuvo el laboratorio con Rspamd y las IPs privadas ([solución de problemas](solucion-de-problemas.md)).
- Marcar los correos **externos** y alertar sobre nombres visibles de directivos con direcciones externas (A6).
- Detectar dominios parecidos al propio (A5).
- Si usas un gateway o un antivirus que **modifica** los correos entrantes (reescribe enlaces, agrega pies), hazlo **después** de verificar DKIM, o usa ARC.

## 6. Mantenimiento

- Revisa los reportes `rua` de forma periódica, y siempre que se contrate un servicio nuevo que envíe correo.
- Agrega al proceso de compras la pregunta "¿este servicio enviará correo con nuestro dominio?".
- Lleva un calendario de rotación de llaves DKIM.
- Considera MTA-STS y TLS-RPT para cifrar el transporte, y BIMI cuando estés en `p=quarantine` o `p=reject`.

## 7. Lista de verificación

- [ ] Inventario de fuentes de correo con responsables.
- [ ] SPF: un registro, ≤ 10 consultas, termina en `-all` (o `~all` durante la transición).
- [ ] DKIM: todas las fuentes firman con tu dominio, con llaves de 2048 bits y un selector por fuente.
- [ ] DMARC `p=none` con `rua` y una herramienta para leer los reportes.
- [ ] Fuentes legítimas alineadas según los reportes.
- [ ] `p=quarantine` con `pct=` gradual.
- [ ] `p=reject` y `sp=reject`.
- [ ] Dominios que no envían: `v=spf1 -all`, `p=reject` y MX nulo.
- [ ] Entrada: se aplican las políticas DMARC de los remitentes y se marcan los correos externos.
- [ ] Procesos: confirmación por otro canal de pagos y cambios de cuenta.
