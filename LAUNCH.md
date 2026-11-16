# Kit de lanzamiento

Material para publicar Telaraña y que la encuentre quien la necesita. Todo con un
tono honesto: sin exagerar, diciendo los límites. Es lo que genera confianza.

## Descripción corta (para "About" del repo, 1 línea)

> Defensa autoalojada y gratuita contra bots y scrapers abusivos, para sitios
> pequeños que no pueden pagar una. Degrada en silencio, aprende de sus trampas.

## Descripción de una frase (para redes)

> Los grandes pagan a Cloudflare; los pequeños no tienen nada. Telaraña es una
> defensa contra bots que instalas tú, gratis, sin enviar tu tráfico a nadie.

## Etiquetas (topics de GitHub)

`bot-detection` · `anti-scraping` · `tarpit` · `honeypot` · `self-hosted` ·
`web-security` · `ai-scrapers` · `proof-of-work` · `python` · `aiohttp`

## Borrador de anuncio (foros tipo r/selfhosted, Lobsters)

**Título:** Telaraña: defensa autoalojada contra bots abusivos para sitios pequeños

Los scrapers —sobre todo los de IA— están disparando las facturas de servidor de
blogs, wikis y archivos que no pueden pagar un Cloudflare. Hice Telaraña para
ellos: se instala en tu propio servidor con Docker, no envías tu tráfico a
ninguna empresa, y aprende de los bots que te atacan a ti.

En vez de bloquear (lo que enseña al bot a evadirte), degrada en silencio: el
tráfico limpio pasa, el dudoso resuelve un reto invisible, y el bot confirmado va
a un laberinto, sin saber nunca que lo pillaste. Con cada ataque, el modelo
mejora.

Soy honesto sobre los límites: no logra detección perfecta (eso es imposible);
lo que hace es encarecer la evasión, y la documentación dice qué filtra y qué
no. Y es una herramienta de doble filo, así que trae una guía de uso
responsable y valores por defecto prudentes.

Es software libre (MIT). Se instala en 10 minutos. Feedback bienvenido.

## Borrador corto (Mastodon / Bluesky)

Publiqué Telaraña: una defensa gratuita y autoalojada contra bots y scrapers
abusivos, pensada para los sitios pequeños que no pueden pagar un WAF comercial.
No bloquea: degrada en silencio y aprende de sus propias trampas. MIT, Docker,
10 min. Honesto sobre sus límites y con guía de uso responsable. 🕸️

## FAQ

**¿En qué se diferencia de Cloudflare / DataDome?**
En que es tuyo. No pagas, no envías tu tráfico a un tercero, y aprende de tus
atacantes concretos. A cambio, no tiene la inteligencia global a escala de ellos.
Es una capa que puedes desplegar, no un reemplazo de todo.

**¿Es legal / ético?**
Defender tu propio sitio lo es. Trae `RESPONSIBLE_USE.md` con la línea entre
defender y hacer daño. No la uses contra sitios ajenos.

**¿Va a bloquear a Google?**
No, verifica a los buscadores legítimos por DNS inverso. Revisa `GOOD_BOTS` para
añadir los que te importen.

**¿Necesito ser experto?**
Para instalarlo, no (ver `INSTALL.md`). Para ponerlo delante de tu web real, algo
de conocimiento de servidores ayuda.

**¿Está listo para producción?**
Es una base sólida y verificada, pero para sitios de alto riesgo complétala con
copias de seguridad y buenas prácticas. Las contribuciones son bienvenidas.
