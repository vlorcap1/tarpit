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

¿Funciona todo? `python selftest.py` → debe dar "11/11 comprobaciones superadas".

## Cómo funciona (las cinco capas)

1. **Trampa invisible** — cebos que solo existen en `robots.txt`, únicos por
   visitante. Un humano nunca los pisa; un bot que ignora las reglas, sí.
2. **Aprende de la trampa** — un modelo usa a los bots atrapados para reconocer a
   los siguientes por su comportamiento, antes de que caigan.
3. **Degradación silenciosa** — nunca un error 403; la experiencia empeora poco a
   poco, así el bot no sabe cuándo lo detectaste.
4. **Economía invertida** — al bot confirmado rasparte le cuesta caro (prueba de
   trabajo que exige un navegador real, y respuestas que se inflan al abrirlas) y
   a ti barato.
5. **Autojuego** — la defensa se reentrena contra sus propias evasiones y encarece
   escapar ronda a ronda.

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
| `selfplay.py` | Capa 5: autojuego adversarial |
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

## Honestidad sobre los límites

- No logra detección perfecta: eso es imposible. Lo que hace es **encarecer** la
  evasión hasta forzar al bot a pagar el precio de un navegador real.
- Protege a los bots buenos que verifica y respeta `robots.txt`, pero la
  responsabilidad de no castigar a rastreadores legítimos es tuya: ajusta
  `GOOD_BOTS`.
- Es una base sólida y educativa. Para un sitio de alto riesgo, complétala con
  copias de seguridad, buenas prácticas y, si hace falta, un WAF.

## Licencia

[MIT](LICENSE). Úsalo libremente, en infraestructura propia, con responsabilidad.
