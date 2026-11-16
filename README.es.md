# Telaraña

[![CI](https://github.com/vlorcap1/telarana/actions/workflows/ci.yml/badge.svg)](https://github.com/vlorcap1/telarana/actions/workflows/ci.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

**Detección de bots por trampas para tu proxy inverso.**
[Read in English](README.md)

Telaraña atrapa a los rastreadores que leen tu `robots.txt` y van justo
adonde les dice que no vayan, o que siguen enlaces que ninguna persona puede
ver. Se conecta a nginx, Caddy o Traefik como servicio de autorización
(*forward auth*) y le dice a tu proxy, en cada petición, si el visitante es
`clean` (limpio), `suspect` (sospechoso) o `trapped` (atrapado). Tu proxy
decide qué hacer.

- **Pocos falsos positivos por diseño.** Cada visitante recibe sus propias
  rutas trampa firmadas. Una persona nunca las pide, y un rastreador que
  respeta las reglas tampoco. Los buscadores verificados por DNS nunca se
  penalizan.
- **Explicable.** Cada veredicto trae una puntuación y sus motivos, en
  cabeceras de respuesta, registros y métricas.
- **Seguro de desplegar.** Arranca en modo "solo observar". Con nginx, una
  caída de Telaraña nunca tumba tu sitio (*fail-open*).
- **Pequeño y autoalojado.** Un solo binario de Go (imagen de contenedor de
  14 MB), sin dependencias, sin enviar datos a nadie.

## Cómo funciona

```
                       ┌──────────────────────────────────────────────┐
  visitante ──► proxy ─┤ /robots.txt, /restricted/*  ──► Telaraña      │
                       │ todo lo demás: pregunta /check ──► Telaraña   │
                       │      cabeceras de veredicto ◄──┘              │
                       │ luego sirve, bloquea o desvía ──► tu sitio    │
                       └──────────────────────────────────────────────┘
```

1. **Trampas en robots.txt.** Telaraña sirve tu `robots.txt` con tus propias
   reglas, más un `Disallow` para la zona trampa y tres rutas tentadoras
   (`/restricted/db-dump.sql-3f9a…`) únicas para cada visitante y firmadas con
   HMAC.
2. **Doble puerta.** La primera petición a una trampa devuelve una página
   señuelo creíble con un enlace a una segunda trampa. Una persona curiosa que
   tecleó una ruta de `robots.txt` se queda ahí (veredicto `suspect`); un
   rastreador que sigue todos los enlaces pide la segunda y queda `trapped`.
3. **Detección de listas compartidas.** Una ruta trampa firmada para *otra*
   dirección significa que el rastreador la obtuvo de otra parte (listas de
   rastreo compartidas o reutilizadas): `trapped` de inmediato.
4. **Trampa de enlace (opcional).** Agrega en tus páginas un enlace oculto a
   la zona trampa, por ejemplo
   `<a href="/restricted/archive" hidden>archive</a>`. Es invisible para las
   personas y los lectores de pantalla, está prohibido para los rastreadores
   que respetan las reglas, y atrapa a los scrapers que siguen enlaces sin leer
   `robots.txt`.
5. **Veredictos.** En cada `/check`, Telaraña combina el estado de las trampas
   con señales más débiles (un supuesto buscador que no pasa la verificación
   DNS, el ritmo de peticiones, un User-Agent de librería HTTP) en una
   puntuación. Solo las trampas pueden producir `trapped`.

Un visitante es la pareja *dirección + User-Agent* (las direcciones IPv6 se
agrupan por /64). Así, un bot atrapado detrás de una IP compartida (oficina,
universidad, red móvil) no arrastra a sus vecinos.

## Dónde encaja

Telaraña es una **señal de detección**, no una defensa completa. Complementa a:

| Herramienta | Qué hace | Con Telaraña |
|---|---|---|
| Retos (p. ej. Anubis) | Prueba de trabajo para frenar el scraping masivo | Enviar al reto solo a `suspect`/`trapped`, no a todos |
| Laberintos (p. ej. Iocaine, Nepenthes) | Alimentar a los bots con contenido generado sin fin | Desviar ahí a los `trapped` |
| Límite de ritmo | Limita el volumen de peticiones | Atrapa al rastreador lento y "educado" que el límite no ve |
| Gestión de bots alojada (p. ej. Cloudflare) | Reputación global y aprendizaje automático | Una señal propia, explicable y bajo tu control |

Lo que **no** atrapa: un bot que nunca lee `robots.txt` y nunca sigue un
enlace trampa. Para esos, combínalo con límite de ritmo o un reto.

## Inicio rápido

Requiere Docker. Esto levanta nginx delante de una aplicación de ejemplo que
devuelve las cabeceras que recibe:

```sh
git clone https://github.com/vlorcap1/telarana && cd telarana/examples/nginx
export TELARANA_SECRET=$(openssl rand -hex 32)
docker compose up --build
```

Luego, en otra terminal:

```sh
curl -s localhost:8080/ | grep -i telarana          # X-Telarana-Verdict: clean
curl -s localhost:8080/robots.txt                   # tus reglas + rutas trampa
curl -s localhost:8080/restricted/db-dump.sql       # página señuelo
```

## Integraciones

Las configuraciones completas y probadas están en [`examples/`](examples).
Cada una se prueba de extremo a extremo en CI con
[`scripts/e2e.sh`](scripts/e2e.sh).

| Proxy | Mecanismo | Ejemplo | Si Telaraña se cae |
|---|---|---|---|
| nginx | `auth_request` | [examples/nginx](examples/nginx) | **Fail-open** (el sitio sigue funcionando; veredicto `unavailable`) |
| Caddy | `forward_auth` | [examples/caddy](examples/caddy) | Las peticiones fallan (502) |
| Traefik | middleware `ForwardAuth` | [examples/traefik](examples/traefik) | Las peticiones fallan |

Con Caddy y Traefik, ejecuta Telaraña con política de reinicio y su chequeo de
salud, y vigílalo como cualquier otra dependencia de tu sitio.

En todos los casos el proxy debe:

1. Enviar `/robots.txt` y la zona trampa (`/restricted`, `/restricted/*`) a
   Telaraña, pasando la dirección del cliente en `X-Forwarded-For`.
2. Consultar `/check` antes de servir cualquier otra cosa, pasando la ruta
   original en `X-Original-URI` (nginx) o `X-Forwarded-Uri` (Caddy y Traefik
   lo hacen solos).

## Veredictos

`/check` siempre responde con estas cabeceras:

| Cabecera | Ejemplo | Significado |
|---|---|---|
| `X-Telarana-Verdict` | `clean`, `verified-bot`, `suspect`, `trapped` | El veredicto |
| `X-Telarana-Score` | `0`–`100` | 100 solo para trampas confirmadas |
| `X-Telarana-Reasons` | `trap:first-hit,ua:tool` | Por qué |

| Motivo | Puntos | |
|---|---|---|
| `trap:repeat` / `trap:shared` | — | Confirmado: veredicto `trapped`, puntuación 100 |
| `trap:first-hit` | 60 | Pidió una trampa (el señuelo) |
| `goodbot:impostor` | 50 | Dice ser un buscador; el DNS lo desmiente |
| `rate:high` | hasta 30 | Más de `TELARANA_RATE_MAX` peticiones por ventana |
| `ua:tool` | 15 | User-Agent vacío o de librería HTTP (curl, python-requests…) |
| `goodbot:verified` | — | Buscador verificado por DNS: nunca se penaliza |

Una puntuación igual o mayor a `TELARANA_SUSPECT_SCORE` (50 por defecto) es
`suspect`. El ritmo y el User-Agent juntos suman como mucho 45, así que un
script rápido con `curl` nunca es sospechoso por sí solo.

El código de estado es `200`, salvo en modo `enforce` para los visitantes
`trapped`, que reciben `TELARANA_ENFORCE_STATUS` (`403` por defecto). Los
sospechosos siempre reciben `200`: desvíalos con la cabecera de veredicto si
quieres (por ejemplo, a un reto).

## Cómo desplegarlo

1. **Observa** (por defecto). Despliega y revisa durante una o dos semanas las
   líneas `visitor trapped` del registro, el `X-Telarana-Verdict` en los
   registros de acceso y las métricas. Mira a quién atrapa.
2. **Agrega tus rastreadores.** Si un rastreador que te importa aparece como
   impostor, o se verifica por listas de IP en vez de DNS, revisa
   `TELARANA_GOOD_BOTS`.
3. **Aplica.** Pon `TELARANA_MODE=enforce`, o sigue observando y actúa sobre la
   cabecera de veredicto en tu proxy (desvía `trapped` a un laberinto y
   `suspect` a un reto).

## Configuración

Toda la configuración va por variables de entorno. Si hay valores inválidos, el
programa se detiene con un mensaje que lista todos los problemas.

| Variable | Por defecto | Descripción |
|---|---|---|
| `TELARANA_SECRET` | *(obligatoria)* | Al menos 32 caracteres. Firma las rutas trampa. `openssl rand -hex 32` |
| `TELARANA_SECRET_PREVIOUS` | | Secreto anterior, aún aceptado para rutas trampa durante una rotación |
| `TELARANA_MODE` | `observe` | `observe` o `enforce` |
| `TELARANA_ENFORCE_STATUS` | `403` | Estado para visitantes `trapped` en modo enforce (400–599) |
| `TELARANA_TRAP_PREFIX` | `/restricted` | Zona trampa. Elige algo creíble que tu sitio no use |
| `TELARANA_ROBOTS_FILE` | | El `robots.txt` de tu sitio, servido antes de las reglas trampa |
| `TELARANA_TRUSTED_PROXIES` | loopback + rangos privados | IPs/CIDR separados por comas que pueden fijar `X-Forwarded-For` |
| `TELARANA_GOOD_BOTS` | | Rastreadores extra verificables por DNS: `nombre:.dominio1\|.dominio2;nombre2:.dominio3` |
| `TELARANA_SUSPECT_SCORE` | `50` | Puntuación a partir de la cual un visitante es `suspect` |
| `TELARANA_RATE_MAX` | `60` | Peticiones por ventana antes de `rate:high` |
| `TELARANA_RATE_WINDOW` | `10s` | Ventana de ritmo |
| `TELARANA_VISITOR_TTL` | `24h` | Inactividad tras la cual se olvida a un visitante |
| `TELARANA_MAX_VISITORS` | `100000` | Tope de memoria de visitantes recordados |
| `TELARANA_DNS_TIMEOUT` | `2s` | Tiempo máximo de la verificación de rastreadores |
| `TELARANA_LISTEN` | `:8080` | Puerto público (detrás de tu proxy) |
| `TELARANA_ADMIN_LISTEN` | `:9090` | Métricas y salud; `off` para desactivar. Mantenlo privado |
| `TELARANA_LOG_LEVEL` | `info` | `debug` registra cada chequeo no limpio |
| `TELARANA_LOG_FORMAT` | `json` | `json` o `text` |

Rastreadores verificados incluidos: Googlebot, Bingbot, Applebot y YandexBot.
En esta lista solo deben ir rastreadores que documentan verificación por DNS
inverso; uno que publica rangos de IP en su lugar quedaría marcado por error
como impostor.

## Operación

- **Salud:** `GET /healthz` en ambos puertos; `telarana healthcheck` para los
  chequeos de salud de contenedores (lo usa la imagen).
- **Métricas:** `GET /metrics` en el puerto de administración, formato
  Prometheus: `telarana_checks_total{verdict}`,
  `telarana_trap_hits_total{kind}`, `telarana_trapped_total{cause}`,
  `telarana_robots_served_total`,
  `telarana_goodbot_verifications_total{result}`,
  `telarana_enforcements_total`, `telarana_visitors_tracked`.
- **Registros:** JSON estructurado por la salida estándar. `trap hit` y
  `visitor trapped` incluyen dirección, User-Agent y ruta.
- **Rotación del secreto:** pon el nuevo valor en `TELARANA_SECRET` y el
  anterior en `TELARANA_SECRET_PREVIOUS`, reinicia, y quita el anterior un día
  después.
- **Estado:** se guarda en memoria, por instancia. Ejecuta una sola instancia, o
  envía cada cliente siempre a la misma. Un almacenamiento compartido está en
  la hoja de ruta.

## Notas de seguridad

- **Nunca dejes que una caché compartida guarde `/robots.txt`.** Su contenido
  cambia según el visitante; Telaraña envía `Cache-Control: private, no-store`.
  Si hay una CDN delante, asegúrate de que respete esa cabecera o no cachee esa
  ruta.
- **Proxies de confianza.** `X-Forwarded-For` solo se cree si viene de
  `TELARANA_TRUSTED_PROXIES`, recorriendo la cadena desde la derecha. No expongas
  Telaraña directamente a internet; mantén privado el puerto de administración.
- **Señuelos.** La página señuelo y las respuestas de las trampas nunca contienen
  datos reales.

## Uso responsable

Usa Telaraña en infraestructura que operes tú. Está hecha para defender sitios
sin cerrar la web abierta: nunca penaliza a buscadores verificados, mantiene las
rutas trampa fuera del alcance de personas y rastreadores respetuosos, y arranca
en modo observar. Revisa a quién atrapas, y recuerda que la investigación, los
archivos y las herramientas de accesibilidad también rastrean.

## Compilar desde el código

Go 1.23 o posterior:

```sh
go build -o telarana ./cmd/telarana
TELARANA_SECRET=$(openssl rand -hex 32) ./telarana
```

¿Sin Go instalado? `scripts/go.sh` ejecuta las herramientas de Go en Docker
(`scripts/go.sh test ./...`).

## Estado del proyecto

La versión 1 es una reescritura en Go de un prototipo anterior en Python
(guardado como
[v0.1.0](https://github.com/vlorcap1/telarana/releases/tag/v0.1.0)). Mira el
[registro de cambios](CHANGELOG.md). Las contribuciones son bienvenidas: lee
[CONTRIBUTING.md](CONTRIBUTING.md). Reporta vulnerabilidades en privado como
indica [SECURITY.md](SECURITY.md).

## Licencia

[MIT](LICENSE)
