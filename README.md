# Telaraña

**Una defensa gratuita contra bots abusivos, para sitios que no pueden pagar una.**

Los grandes sitios pagan a empresas como Cloudflare o DataDome para frenar a los
robots que raspan su contenido. Un blog, una wiki comunitaria, un archivo sin
ánimo de lucro, una ONG o un proyecto de software libre, no. Y hoy los scrapers
—sobre todo los de IA— les disparan la factura del servidor y a veces los tumban.

Telaraña es para ellos: la instalas en tu propio servidor, no envías tu tráfico a
nadie, no cuesta dinero, y aprende de los bots que te atacan a ti.

> ⚠️ **Antes de usarla, lee [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).** Es una
> herramienta de doble filo y queremos que ayude, no que dañe.

## ¿Es para mí?

Sí, si tienes un sitio web propio que sufre tráfico automatizado abusivo y
quieres defenderlo sin depender de una empresa externa.

No, si buscas una solución gestionada sin tocar nada, o si tu sitio es grande y
crítico: ahí un WAF comercial sigue siendo lo sensato. Telaraña es una capa que
puedes desplegar tú, no un sustituto de todo.

## ¿Qué hace, en una frase?

En vez de bloquear (lo que enseña al bot a evadirte), **degrada en silencio**: al
tráfico limpio lo deja pasar, al dudoso le pone un pequeño reto invisible, y al
bot confirmado lo manda a un laberinto interminable, sin decirle nunca que lo
pilló. Y con cada ataque, **aprende**.

## Empezar

👉 **[Guía de instalación en 10 minutos](INSTALL.md)** — para no expertos.

En resumen, con Docker:

```bash
# edita el secreto en docker-compose.yml, luego:
docker compose up --build
# visita http://localhost/
```

¿Funciona todo? `python selftest.py` → debe terminar con
`RESULTADO: N/N comprobaciones superadas` (todas; sin Node instalado se omiten
las 2 de la prueba de trabajo).

## Cómo funciona (las cinco capas)

1. **Trampa invisible** — cebos que solo existen en `robots.txt`, únicos por
   visitante. Un humano nunca los pisa; un bot que ignora las reglas, sí.
2. **Aprende de la trampa** — un modelo usa a los bots atrapados (y a los
   visitantes que demuestran ser legítimos) para reconocer a los siguientes por
   su comportamiento. No opina hasta tener ejemplos suficientes de ambos, y
   como mucho puede pedir el reto: al laberinto solo se llega por las trampas o
   por señales directas.
3. **Degradación silenciosa** — nunca un error 403; la experiencia empeora poco a
   poco, así el bot no sabe cuándo lo detectaste.
4. **Economía invertida** — al bot rasparte le cuesta más que a ti: prueba de
   trabajo con señales de navegador, laberinto a goteo (acotado para no agotar
   tus conexiones) y, opcionalmente, respuestas que se inflan al abrirlas.
5. **Autojuego (experimental)** — una simulación que muestra cómo reentrenar la
   defensa contra sus propias evasiones encarece escapar. Hoy es una simulación
   con datos sintéticos; todavía no está conectada al servidor.

Los detalles técnicos de cada módulo y la configuración están más abajo.

## Archivos del proyecto

| Archivo | Qué es |
|---|---|
| [INSTALL.md](INSTALL.md) | Instalación en 10 minutos, para cualquiera |
| [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) | Cómo usarlo sin hacer daño. **Léelo.** |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Cómo ayudar al proyecto |
| `app.py` | El servidor que lo orquesta todo |
| `bait.py` | Capa 1: los cebos |
| `classifier.py`, `learner.py` | Capa 2: detección y aprendizaje |
| `maze.py` | Capa 3: el laberinto |
| `asymmetry.py`, `pow.py`, `instrument.py` | Capa 4: economía invertida |
| `selfplay.py` | Capa 5: autojuego adversarial (simulación) |
| `selftest.py` | Comprueba que todo funciona |
| `Dockerfile`, `docker-compose.yml`, `nginx.conf` | Despliegue |

## Configuración (config.py)

- `TARPIT_SECRET` — firma las trampas. **Cámbialo** (en docker-compose.yml).
- `GOOD_BOTS` — rastreadores legítimos que NUNCA deben caer. Amplíala.
- `ASYMMETRY_ON` (por defecto **apagado**) — la respuesta que se infla. Enciéndelo
  solo a conciencia.
- `POW_MIN_BITS` / `POW_MAX_BITS` — dureza de la prueba de trabajo (suave por
  defecto; bájala si tienes visitantes con móviles antiguos).
- `GRAD_SLOW` / `GRAD_TARPIT` — cuándo empeora la respuesta.
- `TARPIT_MAX_CONNS` / `TARPIT_MAX_PER_IP` / `TARPIT_MAX_SECONDS` — límites del
  laberinto a goteo (en total, por IP y duración). Por encima del cupo, la
  página falsa se entrega de golpe. Así retener bots no deja sin conexiones a
  tus visitantes. Si subes la duración, sube también `proxy_read_timeout` en
  `nginx.conf`.
- `TARPIT_TRUST_PROXY` (variable de entorno) — creer la cabecera
  `X-Forwarded-For`. Actívala **solo** con un proxy de confianza delante que la
  reescriba (el `docker-compose.yml` incluido ya lo hace). Sin proxy, cualquiera
  podría inventarse su IP.

## Honestidad sobre los límites

- No logra detección perfecta: eso es imposible. Lo que hace es **encarecer** la
  evasión.
- La prueba de trabajo pide señales de navegador (canvas, pantalla, idioma), pero
  el cliente las genera él mismo y se pueden fabricar. Filtra a clientes
  ingenuos; a un atacante decidido lo cazan, si acaso, las trampas.
- Un "visitante" es la pareja IP + user-agent: si un bot cae en la trampa, no
  arrastra a quienes comparten su IP (oficinas, universidades, redes móviles).
  El ritmo de peticiones sí se mide por IP.
- Protege a los bots buenos que verifica y respeta `robots.txt`, pero la
  responsabilidad de no castigar a rastreadores legítimos es tuya: ajusta
  `GOOD_BOTS`.
- Es una base sólida y educativa. Para un sitio de alto riesgo, complétala con
  copias de seguridad, buenas prácticas y, si hace falta, un WAF.

## Licencia

[MIT](LICENSE). Úsalo libremente, en infraestructura propia, con responsabilidad.
