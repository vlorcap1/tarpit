"""Tarpit asíncrono.

Flujo:
  1. /robots.txt  -> marca que el visitante leyó las reglas y declara
                     Disallow sobre la zona trampa y el laberinto.
  2. /            -> página real + enlace trampa INVISIBLE.
  3. cualquier otra ruta -> se clasifica por comportamiento:
       - bot bueno verificado por DNS  -> contenido normal, nunca al tarpit
       - puntaje bajo en ruta normal   -> 404 limpio
       - cayó en honeypot / laberinto  -> TARPIT con goteo por etapas

El goteo está acotado (conexiones totales, por IP y duración máxima) para que
retener bots no deje sin conexiones a los visitantes reales.
"""

import os
import random
import asyncio

from aiohttp import web

import config
import classifier
import maze
import bait
import learner
import asymmetry
import pow


def client_ip(request):
    """IP del cliente. X-Forwarded-For solo se cree con un proxy de confianza
    delante; se toma la ÚLTIMA entrada, que es la que añadió ese proxy (las
    anteriores las puede escribir el cliente)."""
    if config.TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[-1].strip()
    return request.remote or "0.0.0.0"


def user_agent(request):
    return request.headers.get("User-Agent", "").lower()


class TarpitLimiter:
    """Cupos de respuestas a goteo: en total y por IP. Sin cupo, el laberinto
    se sirve de golpe (barato) en vez de retener otra conexión."""

    def __init__(self, total, per_ip):
        self.total = total
        self.per_ip = per_ip
        self.active = 0
        self.by_ip = {}

    def try_acquire(self, ip):
        if self.active >= self.total or self.by_ip.get(ip, 0) >= self.per_ip:
            return False
        self.active += 1
        self.by_ip[ip] = self.by_ip.get(ip, 0) + 1
        return True

    def release(self, ip):
        self.active = max(0, self.active - 1)
        n = self.by_ip.get(ip, 0) - 1
        if n > 0:
            self.by_ip[ip] = n
        else:
            self.by_ip.pop(ip, None)


limiter = TarpitLimiter(config.TARPIT_MAX_CONNS, config.TARPIT_MAX_PER_IP)


def decide_mode(rule, learned):
    """Decide la respuesta a partir de la sospecha de las reglas (0..1) y la
    del modelo aprendido (0..1).

    Al laberinto solo se llega por las REGLAS (señales directas). El modelo
    aprendido puede equivocarse, así que como mucho pide la prueba de trabajo:
    un humano marcado por error la resuelve sin notarlo, y eso además le enseña
    al modelo un ejemplo de humano.
    Devuelve ("tarpit" | "challenge" | "normal", sospecha_combinada)."""
    suspicion = max(rule, learned)
    if rule >= config.GRAD_TARPIT:
        return "tarpit", suspicion
    if suspicion >= config.GRAD_SLOW:
        return "challenge", min(suspicion, config.GRAD_TARPIT)
    return "normal", suspicion


def label(v, x, is_bot):
    """Envía al modelo como mucho una etiqueta por visitante (no una por
    petición, que inundaría el modelo con el perfil de un solo bot). Un
    visitante etiquetado humano que después pisa un cebo se re-etiqueta bot;
    al revés no."""
    if is_bot:
        if v.label != 1:
            v.label = 1
            learner.learn(x, 1.0)
    elif v.label is None and not v.hit_honeypot:
        v.label = 0
        learner.learn(x, 0.0)


async def robots(request):
    ip = client_ip(request)
    v = classifier.get_visitor(ip, user_agent(request))
    v.fetched_robots = True
    # Cebos jugosos, ÚNICOS para esta IP (firmados con HMAC). No están
    # enlazados en ninguna página: solo existen aquí. Un humano nunca los
    # pide; un bot que husmea robots.txt buscando paths prohibidos, cae.
    # Como cada IP ve rutas distintas, no se pueden memorizar ni compartir.
    lines = ["User-agent: *"]
    for p in bait.bait_paths(ip):
        lines.append(f"Disallow: {p}")
    lines.append(f"Disallow: {config.MAZE_PREFIX}/")
    return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")


# La landing NO contiene ningún enlace oculto por CSS.
# La trampa se entrega de dos formas que no dejan rastro analizable:
#   (1) un enlace señuelo de aspecto totalmente normal que un script
#       ELIMINA del DOM antes de que el humano lo vea (invisibilidad
#       temporal, no espacial: no hay CSS de ocultación que delate nada).
#   (2) una ruta trampa que solo vive en robots.txt (ver handler robots).
LANDING = (
    '<!doctype html><html lang="es"><head><meta charset="utf-8">'
    '<title>Mi sitio</title></head><body>'
    '<h1>Mi sitio</h1>'
    '<p>Bienvenido. Este es el contenido real para personas.</p>'
    '<ul id="nav">'
    '<li><a href="/">Inicio</a></li>'
    '<li id="_d"><a href="{trap}">Ofertas internas</a></li>'  # señuelo normal
    '<li><a href="/">Contacto</a></li>'
    '</ul>'
    # El script borra el <li> señuelo nada más cargar: el humano no lo ve,
    # pero un scraper que lee el HTML crudo ya lo siguió. No hay estilo
    # "oculto" que analizar, porque el enlace nunca fue invisible.
    '<script>(function(){{var d=document.getElementById("_d");'
    'if(d&&d.parentNode)d.parentNode.removeChild(d);}})();</script>'
    '</body></html>'
)


async def landing(request):
    ua = user_agent(request)
    v = classifier.get_visitor(client_ip(request), ua)
    classifier.touch(v)
    await classifier.verify_good_bot(v, ua, asyncio.get_running_loop())
    trap = maze.trap_link(random.Random(os.urandom(8)))
    return web.Response(text=LANDING.format(trap=trap), content_type="text/html")


async def serve_tarpit(request, v, ip):
    seed = os.urandom(12)
    chunks = maze.render_page(seed, v.stage)

    # Sin cupo de goteo: la misma página falsa, pero de golpe. Al bot le sigue
    # pareciendo un sitio más; a ti no te retiene ninguna conexión.
    if not limiter.try_acquire(ip):
        return web.Response(text="".join(chunks), content_type="text/html",
                            headers={"Cache-Control": "no-store"})

    lo, hi = maze.stage_delay(v.stage)
    rng = random.Random(seed)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + config.TARPIT_MAX_SECONDS
    try:
        resp = web.StreamResponse(
            status=200,
            headers={"Content-Type": "text/html; charset=utf-8",
                     "Cache-Control": "no-store"},
        )
        await resp.prepare(request)
        try:
            for i, chunk in enumerate(chunks):
                await resp.write(chunk.encode("utf-8"))
                left = deadline - loop.time()
                if left <= 0:
                    # tiempo agotado: el resto de golpe y se libera la conexión
                    await resp.write("".join(chunks[i + 1:]).encode("utf-8"))
                    break
                await asyncio.sleep(min(rng.uniform(lo, hi), left))  # el goteo
            await resp.write_eof()
        except (ConnectionResetError, asyncio.CancelledError):
            pass  # el bot se rindió: objetivo cumplido
        return resp
    finally:
        limiter.release(ip)


async def fake_admin(request, v, ip):
    """Primera puerta: página falsa y convincente que esconde una SEGUNDA
    ruta prohibida. Un humano despistado que tecleó la URL se detiene aquí;
    un bot que devora enlaces sigue el segundo cebo y se confirma solo."""
    others = [p for p in bait.bait_paths(ip) if p != request.path]
    nxt = others[0] if others else bait.bait_paths(ip)[0]
    html = ('<!doctype html><html lang="es"><head><meta charset="utf-8">'
            '<title>Panel interno</title></head><body>'
            '<h1>Panel de administración</h1>'
            '<p>Acceso restringido. Recursos internos disponibles:</p>'
            f'<ul><li><a href="{nxt}">Exportar base de datos completa</a></li></ul>'
            '</body></html>')
    return web.Response(text=html, content_type="text/html")


REAL_PAGE = ('<!doctype html><html lang="es"><head><meta charset="utf-8">'
             '<title>Mi sitio</title></head><body><h1>Mi sitio</h1>'
             '<p>Contenido real del sitio para personas.</p></body></html>')


async def serve_asymmetric(request, v):
    """Respuesta diminuta en red, pesada al descomprimir. Solo bots confirmados."""
    body = asymmetry.payload()
    resp = web.Response(
        body=body,
        headers={"Content-Type": "text/html; charset=utf-8",
                 "Content-Encoding": "gzip",
                 "Cache-Control": "no-store"},
    )
    return resp


async def serve_slow_real(request):
    """Degradación silenciosa: contenido real, pero servido despacio.
    El bot no recibe ninguna señal de bloqueo; solo un sitio lento."""
    resp = web.StreamResponse(status=200,
                              headers={"Content-Type": "text/html; charset=utf-8"})
    await resp.prepare(request)
    try:
        mid = len(REAL_PAGE) // 2
        for part in (REAL_PAGE[:mid], REAL_PAGE[mid:]):
            await resp.write(part.encode())
            await asyncio.sleep(1.6)
        await resp.write_eof()
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return resp


async def catch_all(request):
    ip = client_ip(request)
    ua = user_agent(request)
    v = classifier.get_visitor(ip, ua)
    classifier.touch(v)
    path = request.path
    loop = asyncio.get_running_loop()

    rate = classifier.request_rate(v)
    x = learner.features(v, rate, ua, config.SUSPICIOUS_UA)  # comportamiento

    # Bots buenos verificados: contenido real + etiqueta "humano" para el modelo
    await classifier.verify_good_bot(v, ua, loop)
    if v.verified_good is True:
        label(v, x, is_bot=False)
        return web.Response(text=REAL_PAGE, content_type="text/html")

    # --- ¿cayó en un cebo? La trampa da una etiqueta "bot" de verdad ---
    status = bait.classify(ip, path)
    if status:
        v.hit_honeypot = True
        v.bait_hits += 1
        label(v, x, is_bot=True)              # el modelo aprende este perfil
        if status == "shared":
            v.confirmed = True
        if v.bait_hits == 1 and not v.confirmed:
            return await fake_admin(request, v, ip)   # primera puerta
        v.confirmed = True
        v.stage = max(v.stage, 2)
        if config.ASYMMETRY_ON:                        # bot confirmado: cóbraselo
            return await serve_asymmetric(request, v)
        return await serve_tarpit(request, v, ip)      # segunda puerta

    # --- sospecha combinada: reglas (arranque en frío) + modelo (aprende) ---
    rule = classifier.evaluate(v, path, ua) / 100.0
    learned = learner.predict(x)
    mode, suspicion = decide_mode(rule, learned)

    if path.startswith(config.MAZE_PREFIX):
        v.stage = min(3, max(v.stage, v.hits // 8))
        return await serve_tarpit(request, v, ip)

    # --- DEGRADACIÓN SILENCIOSA: nunca un 403; la experiencia empeora sola ---
    if mode == "tarpit":
        v.stage = min(3, max(v.stage, v.hits // 8))
        return await serve_tarpit(request, v, ip)     # laberinto
    if mode == "challenge":
        if config.POW_ON:
            # ¿ya pagó su prueba de trabajo? (pase de corta duración)
            if pow.check_pass(ip, request.cookies.get("pow_pass", "")):
                return web.Response(text=REAL_PAGE, content_type="text/html")
            # ¿trae una solución válida (con entorno de navegador)? -> pase
            c, n = request.query.get("c"), request.query.get("n")
            e, b = request.query.get("e"), request.query.get("b")
            if c and n and pow.verify_solution(ip, c, n, e, b):
                # Ejemplo de "humano" para el modelo, si nunca pisó un cebo.
                # Sin esto el modelo solo vería bots y acabaría marcando a todos.
                label(v, x, is_bot=False)
                resp = web.Response(status=303, headers={"Location": path})
                resp.set_cookie("pow_pass", pow.issue_pass(ip),
                                max_age=config.POW_PASS_TTL, httponly=True)
                return resp
            # si no, entrega el reto (dificultad según la sospecha)
            diff = pow.difficulty_for(suspicion)
            page = pow.challenge_page(path, pow.make_challenge(ip, diff), diff)
            return web.Response(text=page, content_type="text/html")
        return await serve_slow_real(request)         # real pero lento
    if path == "/":
        return web.Response(text=REAL_PAGE, content_type="text/html")
    return web.Response(status=404, text="No encontrado")  # ruta inexistente normal


def build_app():
    app = web.Application()
    app.router.add_get("/robots.txt", robots)
    app.router.add_get("/", landing)
    app.router.add_route("*", "/{tail:.*}", catch_all)
    return app


if __name__ == "__main__":
    print(f"Tarpit en http://{config.HOST}:{config.PORT}  "
          f"(honeypot: {config.HONEYPOT_PREFIX}, laberinto: {config.MAZE_PREFIX}, "
          f"proxy de confianza: {'sí' if config.TRUST_PROXY else 'no'})")
    web.run_app(build_app(), host=config.HOST, port=config.PORT)
