# Texto de la respuesta SMTP 5xx cuando Rspamd rechaza un correo (milter).
# Como las acciones por puntaje están desactivadas (actions.conf), en el laboratorio
# solo rechaza la política DMARC p=reject. Sin tildes: SMTP es ASCII.
reject_message = "Rechazado por la politica DMARC (p=reject) del dominio del remitente";
