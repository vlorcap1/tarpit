# Uso responsable

Telaraña es una herramienta de doble filo: las mismas técnicas que defienden un
sitio pueden hacer daño si se usan mal. Este documento no es decoración; léelo
antes de desplegar. El objetivo del proyecto es **proteger a sitios pequeños del
scraping abusivo sin dañar la web abierta**.

## Hazlo

- **Úsalo solo en infraestructura tuya** o con permiso explícito por escrito.
- **Protege a los rastreadores legítimos.** Revisa y amplía la lista `GOOD_BOTS`
  en `config.py` con los buscadores, monitores de disponibilidad, archivistas y
  herramientas de accesibilidad que te importen, antes de activar nada en serio.
- **Respeta `robots.txt` como contrato de dos vías.** Si tú pides a los demás que
  lo respeten, tus trampas también deben estar bien señalizadas como zonas
  prohibidas, nunca enlazadas donde navega una persona.
- **Empieza suave.** Deja la asimetría de costes desactivada (es el valor por
  defecto) y sube la dificultad de la prueba de trabajo solo si de verdad lo
  necesitas. Observa primero, endurece después.
- **Vigila los falsos positivos.** Revisa periódicamente a quién estás atrapando.
  Si un visitante real o un bot útil cae, ajusta los umbrales.

## No lo hagas

- **No lo apuntes a sitios ajenos.** No es una herramienta ofensiva.
- **No conviertas la asimetría de costes en un arma.** Va acotada y solo para
  bots confirmados por una razón. Subirla sin límite para intentar tumbar la
  máquina de alguien puede ser ilegal y es contrario al espíritu del proyecto.
- **No trates todo scraping como un ataque.** Investigación académica, archivo
  histórico, buscadores pequeños y accesibilidad también rastrean. No todo bot
  es malo, y una web que se encierra del todo deja de ser común.
- **No confíes en esto como tu única defensa.** Es una capa, no un sustituto de
  buenas prácticas, copias de seguridad y, si tu riesgo es alto, un WAF serio.

## Una tensión que debes conocer

Hay una línea real entre **defender tu sitio** y **encerrar la información**.
Telaraña está diseñada para caer del lado de la defensa: verifica bots buenos,
respeta `robots.txt` y degrada en silencio en vez de bloquear. Pero la decisión
final es tuya. Si tu sitio contiene información de interés público, piensa dos
veces antes de poner trampas agresivas que puedan afectar a quien la busca con
buena fe.

## Privacidad

Telaraña procesa IPs y señales de comportamiento para decidir por petición. No
envía datos a terceros (ese es parte de su valor). Aun así, si lo despliegas
para otras personas, revisa tus obligaciones locales de privacidad y anúncialo
en tu política si corresponde.

## Seguridad

Si encuentras una vulnerabilidad en Telaraña, repórtala de forma privada al
mantenedor antes de divulgarla. Ver CONTRIBUTING.md.
