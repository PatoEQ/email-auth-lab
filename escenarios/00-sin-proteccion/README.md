# Escenario 0: sin protección

## Objetivo

Ver el problema antes de ver la solución. En este escenario, `bancoseguro.test` no publica **ningún** registro de autenticación de correo. Un atacante escribe que es `director@bancoseguro.test` y el correo llega a la bandeja del empleado igual que uno real, sin ninguna alerta.

Es el punto de partida del fraude del CEO (BEC): un correo "del director" pide una transferencia urgente y confidencial.

## Qué se configura

**DNS de `bancoseguro.test`:** solo lo mínimo para recibir correo.

```
@         IN NS   ns.bancoseguro.test.
@         IN MX   10 receptor.bancoseguro.test.
receptor  IN A    172.28.0.25
emisor    IN A    172.28.0.10
```

- No hay registro **SPF**, así que nadie dice qué servidores pueden enviar en nombre del banco.
- No hay llave **DKIM** publicada, y el emisor no firma.
- No hay política **DMARC**, así que nadie le dice al receptor qué hacer con un correo sospechoso.

**Receptor:** Postfix con Rspamd ya verifica SPF, DKIM y DMARC y lo anota en la cabecera `Authentication-Results`. Pero, sin registros que consultar, el resultado de las tres es `none`, y el correo se entrega.

**Atacante (`172.28.0.66`):** un servidor cualquiera, sin relación con el banco. El ataque A1 usa `swaks`:

| Campo | Valor |
|---|---|
| MAIL FROM (sobre) | `director@bancoseguro.test` |
| From: (lo que ve el empleado) | `director@bancoseguro.test` |
| Firma DKIM | ninguna |

## Pasos

```bash
docker compose up -d --build     # la primera vez tarda unos minutos
./lab.sh estado                  # todos los servicios en ✓ ok
./lab.sh reset                   # bandeja vacía y escenario 0
./lab.sh escenario 0             # muestra los registros publicados: ninguno
./lab.sh enviar legit            # el director real escribe desde el servidor del banco
./lab.sh atacar A1               # el atacante se hace pasar por el director
```

En Windows (PowerShell), usa `.\lab.ps1` en lugar de `./lab.sh`.

Abre la bandeja en http://localhost:8025 y compara los dos correos. En cada uno, mira la pestaña **Headers** y busca `Authentication-Results`.

## Resultado esperado

| Envío | Resultado | `Authentication-Results` |
|---|---|---|
| Legítimo (desde `emisor`, 172.28.0.10) | Entregado | `spf=none` · `dkim=none` · `dmarc=none` |
| A1, suplantación directa (desde 172.28.0.66) | Entregado | `spf=none` · `dkim=none` · `dmarc=none` |

En la bandeja, los dos correos dicen venir de `director@bancoseguro.test`. **Para el empleado son indistinguibles.** La única diferencia está en las cabeceras técnicas, en la IP de origen (`when checking 172.28.0.66`), y nadie la revisa.

La salida de `./lab.sh atacar A1` es parecida a esta:

```
A1 · Suplantación directa
  Sobre (MAIL FROM): director@bancoseguro.test
  Remitente visible (From:): director@bancoseguro.test
  Firma DKIM: ninguna
  Respuesta SMTP: 250 2.0.0 Ok: queued as 59F9035438
  ACEPTADO: el receptor recibió el correo para entregarlo.
  Llegó a la bandeja del empleado (Mailpit).  spf=none  dkim=none  dmarc=none
  Qué significa: bancoseguro.test no publica SPF: no hay nada que verificar.
```

Verificación automática:

```bash
docker compose run --rm toolbox pytest -q tests/test_matriz.py tests/test_fase2.py
```

## Qué aprendimos y qué sigue sin cubrirse

- **SMTP no verifica al remitente.** Tanto la dirección del sobre (`MAIL FROM`) como el `From:` visible los escribe quien envía. Cualquiera puede poner lo que quiera.
- `none` no significa "falló", sino "**no hay nada que verificar**". El receptor sí hizo las comprobaciones, pero el dominio no publicó ninguna regla.
- Sin reglas publicadas por el dueño del dominio, el receptor no tiene en qué basarse para distinguir el correo legítimo del falso.

Sigue sin cubrirse **todo**. El siguiente paso es el [escenario 1](../01-spf/README.md), donde el banco publica SPF para decir desde qué IP envía su correo.

## Preguntas para la audiencia

1. Si el empleado mira solo el remitente en su cliente de correo, ¿tiene alguna forma de detectar el fraude?
2. ¿Qué información tiene el receptor para decidir si el correo es legítimo? ¿Qué le falta?
3. ¿Quién debería publicar las reglas: el banco que envía, el que recibe o los dos?
4. ¿Su organización publica SPF, DKIM y DMARC para todos sus dominios, incluidos los que no envían correo?
