# Glosario

| Término | Significado |
|---|---|
| **Alineación** | En DMARC, que el dominio validado por SPF (el del sobre) o por DKIM (`d=`) coincida con el dominio del `From:`. Puede ser **relajada** (mismo dominio organizacional) o **estricta** (dominio exacto) |
| **ARC** | *Authenticated Received Chain* (RFC 8617). Permite que un intermediario, como una lista de correo, certifique los resultados de autenticación que vio antes de modificar el correo |
| **`Authentication-Results`** | Cabecera (RFC 8601) que agrega el receptor con los resultados de SPF, DKIM y DMARC. Es lo que lee `lab explicar ultimo` |
| **BEC** | *Business Email Compromise*. Fraude que suplanta a un directivo o a un proveedor para conseguir pagos o datos. Incluye el "fraude del CEO" |
| **BIMI** | *Brand Indicators for Message Identification*. Muestra el logo del remitente en algunos clientes, si el dominio tiene DMARC en `quarantine` o `reject` |
| **Canonicalización** | Normalización del correo antes de calcular la firma DKIM (`c=`). `relaxed` tolera cambios menores de espacios y mayúsculas; `simple` no tolera ninguno |
| **Cuarentena** | Política DMARC `p=quarantine`: el correo que falla se entrega marcado como sospechoso. En el laboratorio se ve como `[CUARENTENA]` en el asunto |
| **DKIM** | *DomainKeys Identified Mail* (RFC 6376). Firma criptográfica del correo con la llave privada de un dominio; la pública se publica en DNS |
| **DMARC** | *Domain-based Message Authentication, Reporting and Conformance* (RFC 7489). Exige alineación con el `From:`, define la política (`none`, `quarantine`, `reject`) y pide reportes |
| **Dominio organizacional** | La parte "registrable" de un dominio (`bancoseguro.test` para `mail.bancoseguro.test`). Se usa para la alineación relajada |
| **Dominio parecido** (*lookalike*, *typosquatting*) | Un dominio que imita a otro: `bancos3guro.test` en lugar de `bancoseguro.test` (ataque A5) |
| **Envelope from / sobre / `MAIL FROM` / Return-Path** | El remitente que se declara en la conversación SMTP. Recibe los rebotes y es el que valida SPF. El usuario no lo ve |
| **Header from / `From:`** | El remitente que muestra el cliente de correo. Es el que protege DMARC |
| **MTA** | *Mail Transfer Agent*: un servidor que transporta correo (Postfix en el laboratorio) |
| **Milter** | Interfaz de Postfix y Sendmail para que un programa externo revise o modifique el correo durante la recepción (OpenDKIM y Rspamd en el laboratorio) |
| **MX** | Registro DNS que indica qué servidor recibe el correo de un dominio. Un **MX nulo** (`MX 0 .`, RFC 7505) indica que el dominio no recibe correo |
| **Nombre visible** (*display name*) | El texto antes de la dirección: `"Director General" <urgente@atacante.test>`. No lo verifica ningún protocolo (ataque A6) |
| **Política** (`p=`) | Lo que pide el dueño del dominio para el correo que falla DMARC: `none` (observar), `quarantine` (marcar), `reject` (rechazar) |
| **`pct=`** | Porcentaje de los correos que fallan al que se aplica la política DMARC. Sirve para endurecerla de forma gradual |
| **Rechazo 5xx** | Respuesta SMTP de error permanente (por ejemplo, `554 5.7.1`). El correo no se entrega y el remitente recibe el error |
| **Reenvío** | Reexpedir un correo recibido a otra dirección. Cambia la IP de origen (SPF falla); DKIM sobrevive si no se modifica el contenido |
| **Reporte agregado** (`rua=`) | XML diario que cada receptor envía al dueño del dominio con un resumen de quién envió correo con ese dominio y con qué resultado |
| **Selector** (`s=`) | Nombre que identifica una llave DKIM dentro de un dominio (`s2026` → `s2026._domainkey.bancoseguro.test`) |
| **Serial SOA** | Número de versión de una zona DNS. CoreDNS recarga la zona cuando cambia. En el laboratorio tiene el formato `AAAAMMDDnn` |
| **SMTP** | *Simple Mail Transfer Protocol* (RFC 5321): el protocolo que transporta el correo entre servidores |
| **SPF** | *Sender Policy Framework* (RFC 7208). Lista, publicada en DNS, de las IPs autorizadas para enviar correo con un dominio en el sobre |
| **SRS** | *Sender Rewriting Scheme*: reescribe el sobre al reenviar para que SPF no falle. No ayuda a DMARC |
| **`sp=`** | Política DMARC para los subdominios |
| **swaks** | *Swiss Army Knife for SMTP*: herramienta de línea de comandos para enviar correo de prueba. La usa el atacante del laboratorio |
| **TTL** | *Time To Live*: cuántos segundos puede guardarse en caché un registro DNS. En el laboratorio es de 5 s |
| **`.test`** | Dominio de primer nivel reservado para pruebas (RFC 2606): nunca existe en Internet |
| **192.0.2.0/24** | Rango de IPs reservado para documentación (TEST-NET-1, RFC 5737). Lo usa el reporte DMARC de ejemplo |
