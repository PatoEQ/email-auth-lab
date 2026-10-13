# Rspamd trata los rangos privados como "locales" y se salta SPF y DMARC para ellos.
# En el laboratorio todo el tráfico viene de 172.28.0.0/24, así que hay que forzar
# las verificaciones:
#  - local_addrs: solo localhost se considera red local.
#  - check_local: los módulos que preguntan ip:is_local() (RFC 1918) igual verifican.
#    spf.lua y dmarc.lua leen este valor de su propia sección o, si no existe, de aquí.
local_addrs = ["127.0.0.0/8", "::1"];
check_local = true;

# Resolvedor del laboratorio (CoreDNS).
dns {
  nameserver = ["172.28.0.53"];
  timeout = 2s;
  retransmits = 2;
}
