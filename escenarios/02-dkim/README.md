# Escenario 2: DKIM

## Objetivo

Ver qué agrega **DKIM** a SPF. El servidor del banco firma cada correo con una llave privada y publica la llave pública en el DNS. Así el receptor puede comprobar **quién firmó** el correo y **que nadie lo modificó** por el camino. Con eso se detecta A3, el correo legítimo alterado. Pero A4 demuestra que una firma válida no garantiza que el remitente visible sea auténtico.

## Qué se configura

**DNS de `bancoseguro.test`:** se mantiene el SPF y se agrega la llave pública DKIM, con el selector `s2026`.

```
@                 IN TXT  "v=spf1 ip4:172.28.0.10 -all"
s2026._domainkey  IN TXT  ( "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…" "…" )
```

- El nombre es `<selector>._domainkey.<dominio>`. El selector permite tener varias llaves a la vez, por ejemplo para rotarlas o para que un proveedor externo firme con la suya.
- `p=` es la llave pública RSA de 2048 bits. No cabe en una sola cadena TXT (máximo 255 caracteres), así que va partida en varias.
- La llave privada la genera el servicio `init` al arrancar (`opendkim-genkey -b 2048`). Vive en el volumen `llaves` y **nunca** está en el repositorio.

**Emisor:** Postfix usa **OpenDKIM** como milter y firma con `d=bancoseguro.test` y `s=s2026`. Solo firma si el escenario activo lo pide (escenarios 2 en adelante). El emisor lee el escenario de `estado/estado.json`, pone o quita el milter con `postfix reload` y confirma el cambio en `estado/emisor.json`. No hay que reiniciar contenedores ni montar `docker.sock`.

**Atacante:** su dominio `atacante.test` también tiene llave DKIM (`a2026._domainkey.atacante.test`). El contenedor del atacante solo tiene sus propias llaves privadas; la del banco nunca se monta ahí. Ataques nuevos:

| | A3 · Correo legítimo alterado | A4 · Firma con su propio dominio |
|---|---|---|
| MAIL FROM (sobre) | `director@bancoseguro.test` | `rebote@atacante.test` |
| From: (lo que ve el empleado) | `Director General <director@bancoseguro.test>` | `director@bancoseguro.test` |
| Firma DKIM | la **original** del banco, copiada tal cual | una nueva con `d=atacante.test`, `s=a2026` |
| Cuerpo | el del correo legítimo, con la cuenta `0012-3456-78` cambiada por `9999-6666-00` | el texto de "transferencia urgente" |

En A3, el atacante toma el último correo legítimo firmado de la bandeja (en el laboratorio lo lee de la API de Mailpit). Le quita las cabeceras de entrega (`Received`, `Authentication-Results`…), cambia el número de cuenta y lo reenvía con todas las demás cabeceras intactas, incluida la firma. En la vida real, el atacante podría conseguir ese correo a través de una cuenta comprometida, un reenvío o un proveedor que lo recibió.

## Pasos

```bash
./lab.sh reset
./lab.sh escenario 2      # SPF + llave DKIM; el emisor confirma que firma
./lab.sh enviar legit     # correo real, firmado por bancoseguro.test
./lab.sh atacar A3        # el mismo correo con otra cuenta bancaria
./lab.sh atacar A4        # From: del director, firmado por atacante.test
./lab.sh atacar A1        # para comparar: sin firma
```

En PowerShell, usa `.\lab.ps1` en lugar de `./lab.sh`.

En http://localhost:8025, abre el correo legítimo y el de A3. Tienen el mismo asunto, el mismo remitente y el mismo `Message-ID`. Compara la cuenta bancaria del cuerpo y la cabecera `Authentication-Results` de cada uno.

## Resultado esperado

| Envío | Resultado | `Authentication-Results` |
|---|---|---|
| Legítimo | Entregado | `spf=pass` · `dkim=pass header.d=bancoseguro.test header.s=s2026` |
| A1 | Entregado | `spf=fail` · `dkim=none` |
| A2 | Entregado | `spf=pass` (de `atacante.test`) · `dkim=none` |
| A3 | Entregado | `spf=fail` · `dkim=fail ("body hash did not verify") header.d=bancoseguro.test` |
| A4 | Entregado | `spf=pass` (de `atacante.test`) · `dkim=pass header.d=atacante.test header.s=a2026` |

Todos llegan: DKIM, como SPF, solo **informa**. La decisión de rechazar llega con DMARC.

### Anatomía de una firma DKIM

Esta es la firma real que agrega el emisor del laboratorio:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bancoseguro.test;
	s=s2026; t=1791876047;
	bh=9a8lLOE6a4dmxmImYAYa443GzIJhxXyDyll2g4+Fjsk=;
	h=From:To:Subject:Date:Message-ID:Content-Type:
	 Content-Transfer-Encoding:MIME-Version:From;
	b=MP8iV2J0wQ1Fifx//k90avhkcVho2n26LCwZp48A2bQXNEcFaUi7915EZJheVcPQv
	 20j/chUOACW4c9m9zjCZn4ryvEXh4LdFnn4+55fm8Hf56usjEhzsVVXTjiFD0bQ8uI
	 …
```

| Campo | Qué es | En el ejemplo |
|---|---|---|
| **`d=`** | **Dominio que firma** y se hace responsable del correo. El receptor busca la llave pública en este dominio. | `bancoseguro.test` |
| **`s=`** | **Selector**: indica cuál de las llaves del dominio se usó. El receptor consulta el TXT de `<s>._domainkey.<d>`. | `s2026` → `s2026._domainkey.bancoseguro.test` |
| **`bh=`** | **Hash del cuerpo** (*body hash*): un SHA-256 del cuerpo del mensaje, en base64. Si cambia una sola letra del cuerpo, cambia el hash. | `9a8lLOE6…` |
| **`b=`** | **La firma** en sí: el RSA, hecho con la llave privada, de las cabeceras listadas en `h=` y de la propia `DKIM-Signature` (que incluye `bh=`). Solo puede generarla quien tiene la llave privada. | `MP8iV2J0…` |
| `h=` | Cabeceras cubiertas por la firma. `From` aparece dos veces (*oversigning*) para que nadie pueda agregar un segundo `From:` sin romperla. | `From:To:Subject:Date:Message-ID:…:From` |
| `a=` / `c=` | Algoritmo (`rsa-sha256`) y canonicalización (`relaxed/relaxed`), que tolera cambios menores de espacios en tránsito. | |
| `t=` | Momento de la firma (segundos desde 1970). | |

**Cómo verifica el receptor:**

1. Lee `d=` y `s=` y consulta el TXT `s2026._domainkey.bancoseguro.test`, de donde obtiene la llave pública.
2. Calcula el hash del cuerpo que recibió y lo compara con `bh=`. Si no coinciden, el resultado es `dkim=fail ("body hash did not verify")`.
3. Con la llave pública, comprueba que `b=` corresponde a las cabeceras de `h=`. Si no, el resultado es `dkim=fail` por la firma.
4. Si todo coincide, el resultado es `dkim=pass header.d=bancoseguro.test`.

### Por qué A3 falla y A4 pasa

- **A3:** el atacante copió la firma original, pero cambió la cuenta del cuerpo. El `bh=` sigue siendo el hash del cuerpo **original**, y el receptor calcula uno distinto: **`body hash did not verify`**. El atacante tampoco puede rehacer `bh=`, porque `bh=` forma parte de lo firmado en `b=` y no tiene la llave privada del banco. **DKIM detecta la modificación.**
- **A4:** la firma es auténtica y correcta. Pero es de **`atacante.test`**: el receptor buscó la llave en `a2026._domainkey.atacante.test`, y todo coincidió. DKIM prueba que `atacante.test` firmó el correo, **no** que el correo venga de `bancoseguro.test`. El empleado sigue viendo `director@bancoseguro.test` en el `From:`, y DKIM no compara `d=` con ese dominio.

## Qué aprendimos y qué sigue sin cubrirse

- DKIM protege la **integridad**: si alguien altera el cuerpo o las cabeceras firmadas, la firma falla (A3).
- DKIM **sobrevive al reenvío** mientras no se modifique el contenido. SPF no, porque cambia la IP (lo veremos en el escenario 5).
- `dkim=pass` solo dice que **algún** dominio firmó. Ese dominio puede ser cualquiera, incluso el del atacante (A4).
- Un `dkim=fail` tampoco detiene nada: el correo de A3, con la cuenta del atacante, **llegó** a la bandeja.
- Sigue sin cubrirse:
  - la **alineación**: que el dominio de SPF o de DKIM coincida con el del `From:` visible;
  - la **política**: qué debe hacer el receptor cuando falla.

  Las dos cosas las aporta DMARC, en el [escenario 3](../03-dmarc/README.md).

## Preguntas para la audiencia

1. Si un correo tiene `dkim=pass`, ¿qué dominio deben mirar para saber si el resultado sirve de algo?
2. En A3, ¿por qué el atacante no puede recalcular el `bh=` para que coincida con el cuerpo nuevo?
3. ¿Qué pasaría si la llave privada del banco se filtrara? ¿Cómo ayuda el selector a reemplazarla?
4. ¿Qué servicios externos firman correo en nombre de su organización? ¿Con qué `d=` lo hacen?
