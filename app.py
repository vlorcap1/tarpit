"""Tarpit asíncrono.

Flujo:
  1. /robots.txt  -> marca que el visitante leyó las reglas y declara
                     Disallow sobre la zona trampa y el laberinto.
  2. /            -> página real + enlace trampa INVISIBLE.
  3. cualquier otra ruta -> se clasifica por comportamiento:
       - bot bueno verificado por DNS  -> contenido normal, nunca al tarpit
       - puntaje bajo en ruta normal   -> 404 limpio
       - cayó en honeypot / laberinto  -> TARPIT con goteo por etapas
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
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote or "0.0.0.0"


async def robots(request):
    ip = client_ip(request)
    v = classifier.get_visitor(ip)
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
    v = classifier.get_visitor(client_ip(request))
    classifier.touch(v)
    ua = request.headers.get("User-Agent", "").lower()
    await classifier.verify_good_bot(v, ua, asyncio.get_event_loop())
    trap = maze.trap_link(random.Random(os.urandom(8)))
    return web.Response(text=LANDING.format(trap=trap), content_type="text/html")


async def serve_tarpit(request, v):
    seed = os.urandom(12)
    chunks = maze.render_page(seed, v.stage)
    lo, hi = maze.stage_delay(v.stage)
    rng = random.Random(seed)

    resp = web.StreamResponse(
        status=200,
        headers={"Content-Type": "text/html; charset=utf-8",
                 "Cache-Control": "no-store"},
    )
    await resp.prepare(request)
    try:
        for chunk in chunks:
            await resp.write(chunk.encode("utf-8"))
            await asyncio.sleep(rng.uniform(lo, hi))  # el goteo que lo atasca
        await resp.write_eof()
    except (ConnectionResetError, asyncio.CancelledError):
        pass  # el bot se rindió: objetivo cumplido
    return resp


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
    v = classifier.get_visitor(ip)
    classifier.touch(v)
    path = request.path
    ua = request.headers.get("User-Agent", "").lower()
    loop = asyncio.get_event_loop()

    rate = classifier.request_rate(v)
    x = learner.features(v, rate, ua, config.SUSPICIOUS_UA)  # comportamiento

    # Bots buenos verificados: contenido real + etiqueta "humano" para el modelo
    await classifier.verify_good_bot(v, ua, loop)
    if v.verified_good is True:
        learner.learn(x, 0.0)
        return web.Response(text=REAL_PAGE, content_type="text/html")

    # --- ¿cayó en un cebo? La trampa da una etiqueta "bot" de verdad ---
    status = bait.classify(ip, path)
    if status:
        v.hit_honeypot = True
        v.bait_hits += 1
        learner.learn(x, 1.0)                 # el modelo aprende este perfil
        if status == "shared":
            v.confirmed = True
        if v.bait_hits == 1 and not v.confirmed:
            return await fake_admin(request, v, ip)   # primera puerta
        v.confirmed = True
        v.stage = max(v.stage, 2)
        if config.ASYMMETRY_ON:                        # bot confirmado: cóbraselo
            return await serve_asymmetric(request, v)
        return await serve_tarpit(request, v)          # segunda puerta

    # --- sospecha combinada: reglas (arranque en frío) + modelo (aprende) ---
    rule = classifier.evaluate(v, path, ua) / 100.0
    learned = learner.predict(x)
    suspicion = max(rule, learned)

    if path.startswith(config.MAZE_PREFIX):
        v.stage = min(3, max(v.stage, v.hits // 8))
        return await serve_tarpit(request, v)

    # --- DEGRADACIÓN SILENCIOSA: nunca un 403; la experiencia empeora sola ---
    if suspicion >= config.GRAD_TARPIT:
        v.stage = min(3, max(v.stage, v.hits // 8))
        return await serve_tarpit(request, v)         # laberinto
    if suspicion >= config.GRAD_SLOW:
        if config.POW_ON:
            # ¿ya pagó su prueba de trabajo? (pase de corta duración)
            if pow.check_pass(ip, request.cookies.get("pow_pass", "")):
                return web.Response(text=REAL_PAGE, content_type="text/html")
            # ¿trae una solución válida (con entorno de navegador)? -> pase
            c, n = request.query.get("c"), request.query.get("n")
            e, b = request.query.get("e"), request.query.get("b")
            if c and n and pow.verify_solution(ip, c, n, e, b):
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
          f"(honeypot: {config.HONEYPOT_PREFIX}, laberinto: {config.MAZE_PREFIX})")
    web.run_app(build_app(), host=config.HOST, port=config.PORT)
