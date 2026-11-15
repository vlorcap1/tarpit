# Instalar Telaraña en 10 minutos

Guía para alguien que **no es experto en seguridad**. Si sabes copiar y pegar en
una terminal, puedes hacerlo. Protegerás tu sitio de bots abusivos sin enviar tu
tráfico a ninguna empresa.

> Antes de empezar: lee `RESPONSIBLE_USE.md`. Son dos minutos y evita sustos.

## Lo que necesitas

- Un servidor (o tu ordenador para probar) con **Docker** instalado.
  Si no lo tienes: https://docs.docker.com/get-docker/
- 10 minutos.

## Paso 1 — Descarga el proyecto

Descomprime `telarana-tarpit.zip`. Verás una carpeta `tarpit/` con los archivos.
Abre una terminal dentro de esa carpeta.

## Paso 2 — Pon tu secreto

Abre `docker-compose.yml` con cualquier editor de texto y cambia esta línea:

```yaml
TARPIT_SECRET: "cambia-esto-por-un-secreto-largo-y-aleatorio"
```

Pon cualquier texto largo y difícil de adivinar. Guárdalo.

## Paso 3 — Enciéndelo

En la terminal, dentro de la carpeta `tarpit/`:

```bash
docker compose up --build
```

Espera a que termine. Cuando veas que no para de escribir, ya está corriendo.

## Paso 4 — Compruébalo

Abre otra terminal y escribe:

```bash
curl http://localhost/                 # deberías ver "Mi sitio"
curl http://localhost/robots.txt       # verás tus rutas-trampa únicas
```

¡Listo! Telaraña está funcionando en el puerto 80.

## Paso 5 — Protege tus bots buenos (importante)

Para no atrapar por error a Google, Bing o monitores que uses, abre `config.py`
y revisa la lista `GOOD_BOTS`. Añade los que necesites. Luego reinicia:

```bash
docker compose restart
```

## Paso 6 — Ponlo delante de tu web real

Esta versión sirve una página de ejemplo. Para proteger **tu** sitio, edita
`nginx.conf` para que, cuando un visitante sea legítimo, el tráfico vaya a tu
aplicación real en lugar de a la página de ejemplo. Si no sabes hacerlo, pide
ayuda: es el único paso que requiere algo de conocimiento de servidores, y
depende de cómo esté montada tu web.

## ¿Funciona todo?

Para verificarlo sin Docker, con Python instalado:

```bash
pip install -r requirements.txt
python selftest.py          # debe terminar con "RESULTADO: N/N comprobaciones superadas"
```

## Problemas comunes

- **"Todas las IPs parecen la misma"**: tu proxy no está pasando la IP real.
  El `nginx.conf` incluido ya lo hace; si usas otro proxy, asegúrate de que
  envía la cabecera `X-Forwarded-For` y activa `TARPIT_TRUST_PROXY=1`.
  Nunca la actives si el tarpit queda expuesto directamente a internet.
- **"Un visitante real quedó atrapado"**: baja los umbrales en `config.py`
  (`GRAD_SLOW`, `GRAD_TARPIT`) o añade su bot a `GOOD_BOTS`.
- **"La prueba de trabajo tarda mucho en móviles"**: baja `POW_MAX_BITS`.

## ¿Necesitas ayuda?

Mira `README.md` para los detalles, y `CONTRIBUTING.md` si quieres preguntar o
aportar. No estás solo.
