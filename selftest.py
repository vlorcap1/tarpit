"""Autodiagnóstico: comprueba que cada capa funciona. Ejecuta `python selftest.py`."""

import asyncio
import os
import tempfile

# Pruebas herméticas: el modelo de prueba no toca tu weights.json real.
_TMP = tempfile.mkdtemp(prefix="telarana-selftest-")
os.environ["TARPIT_WEIGHTS"] = os.path.join(_TMP, "weights.json")

import config
import classifier
import bait
import learner
import pow
import instrument
import selfplay
import asymmetry
import app
from aiohttp.test_utils import make_mocked_request, TestClient, TestServer

OK, FAIL = "  ok ", "FAIL "
results = []


def check(name, cond):
    results.append((bool(cond), name))
    print(("[%s] " % (OK if cond else FAIL)) + name)


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# Capa 1: cebos por IP, firmados, con detección de compartido
pa = bait.bait_paths("1.1.1.1")
pb = bait.bait_paths("2.2.2.2")
check("Cebos únicos por IP", set(pa).isdisjoint(pb))
check("Clasifica cebo propio", bait.classify("1.1.1.1", pa[0]) == "own")
check("Detecta cebo compartido", bait.classify("2.2.2.2", pa[0]) == "shared")

# Capa 2: el modelo aprende de etiquetas de la trampa
import random
import time
from collections import deque


def _mk(bot):
    v = classifier.Visitor("x")
    now = time.time()
    v.timestamps = deque(now + i * (0.2 if bot else 3.0) for i in range(8))
    return v, ("curl" if bot else "mozilla/5.0"), (40 if bot else 3)


susp = config.SUSPICIOUS_UA
learner.reset()
for _ in range(300):
    b = os.urandom(1)[0] % 2 == 0
    v, ua, rate = _mk(b)
    learner.learn(learner.features(v, rate, ua, susp), 1.0 if b else 0.0)
acc = 0
for _ in range(200):
    b = os.urandom(1)[0] % 2 == 0
    v, ua, rate = _mk(b)
    acc += (learner.predict(learner.features(v, rate, ua, susp)) > 0.5) == b
check("El modelo aprende (precisión > 85%)", acc / 200 > 0.85)

# Vector de un humano normal: ritmo bajo, navegador, no leyó robots.txt
HUMANO = [0.05, 0.0, 0.0, 0.0, 0.2]

# Caso real de un sitio pequeño: solo llegan etiquetas "bot" de las trampas.
# Antes, el modelo aprendía que TODO visitante es bot (P = 1.0 para un humano).
learner.reset()
for _ in range(200):
    learner.learn([random.random(), 0.0, 0.0, 1.0, random.random()], 1.0)
check("Sin ejemplos de humanos, el modelo no opina",
      not learner.ready() and learner.predict(HUMANO) == 0.0)

# Muy desbalanceado: 400 bots por 30 humanos. Un humano NO debe quedar marcado.
random.seed(7)
learner.reset()
for _ in range(400):
    learner.learn([random.uniform(0.0, 1.0), float(random.random() < 0.5), 0.0,
                   1.0, random.uniform(0.2, 1.0)], 1.0)
    if random.random() < 30 / 400:
        learner.learn([random.uniform(0.0, 0.2), 0.0, 0.0, 0.0,
                       random.uniform(0.0, 0.5)], 0.0)
while len(learner._neg) < learner.MIN_PER_CLASS:
    learner.learn([random.uniform(0.0, 0.2), 0.0, 0.0, 0.0,
                   random.uniform(0.0, 0.5)], 0.0)
p_humano = learner.predict(HUMANO)
p_bot = learner.predict([0.8, 1.0, 0.0, 1.0, 0.9])
check("Con datos desbalanceados, un humano no queda marcado (P=%.2f, bot P=%.2f)"
      % (p_humano, p_bot), learner.ready() and p_humano < config.GRAD_SLOW < p_bot)
learner.reset()

# El modelo solo puede pedir el reto; al laberinto se llega por reglas/trampas
check("El modelo por sí solo nunca manda al laberinto",
      app.decide_mode(0.0, 1.0)[0] == "challenge"
      and app.decide_mode(config.GRAD_TARPIT, 0.0)[0] == "tarpit"
      and app.decide_mode(0.0, 0.0)[0] == "normal")

# Una IP compartida: si un bot cae en la trampa, no arrastra a sus vecinos
vb = classifier.get_visitor("3.3.3.3", "python-requests/2.31")
vb.hit_honeypot = True
vh = classifier.get_visitor("3.3.3.3", "mozilla/5.0 (macintosh)")
check("Misma IP, otro navegador: no hereda la trampa", not vh.hit_honeypot)

# Capa 4b: prueba de trabajo + instrumentación.
# Ojo: este "cliente" es Node, no un navegador. Prueba que la verificación
# funciona, y a la vez que las señales de navegador se pueden fabricar: la
# instrumentación filtra clientes ingenuos, no a un atacante decidido.
import hashlib, json, subprocess
ip, diff = "7.7.7.7", 12
chal = pow.make_challenge(ip, diff)
cli = pow._SHA256_JS + f'''
var C={json.dumps(chal)},D={diff};
function zeros(h){{var n=0;for(var i=0;i<h.length;i++){{var v=parseInt(h[i],16);
if(v===0){{n+=4;continue;}}if(v<2)return n+3;if(v<4)return n+2;if(v<8)return n+1;return n;}}return n;}}
var b="wd=0;lang=es-ES;langs=2;plugins=3;sw=1920;sh=1080;dpr=200;hc=8;cv="+sha256("cv")+";frames=16,17,15,18,16,17";
var E=sha256(b),k=0;while(true){{if(zeros(sha256(C+":"+E+":"+k))>=D)break;k++;}}
console.log(JSON.stringify({{n:k,e:E,b:b}}));'''
try:
    js = os.path.join(_TMP, "_cli.js")
    open(js, "w").write(cli)
    sol = json.loads(subprocess.check_output(["node", js]).decode())
    check("Cliente con señales de navegador resuelve el reto",
          pow.verify_solution(ip, chal, str(sol["n"]), sol["e"], sol["b"]))
    check("Cliente sin señales de navegador rechazado",
          not pow.verify_solution(ip, chal, str(sol["n"]), None, None))
except FileNotFoundError:
    print("[ info] node no disponible: se omite la prueba de PoW de extremo a extremo")

check("webdriver=1 rechazado por instrumentación",
      not instrument.verify(instrument.parse_bundle(
          "wd=1;lang=es;langs=2;plugins=1;sw=800;sh=600;dpr=100;hc=4;cv=" +
          hashlib.sha256(b"x").hexdigest() + ";frames=16,17,15,18,16,17")))

# Capa 4a: asimetría de costes
sent, mb = asymmetry.ratio()
check("Asimetría de costes (ratio > 100:1)", (mb * 1024 * 1024 / sent) > 100)

# Autojuego (simulación): coste de evadir sube frente a defensa estática
random.seed(1)
sim = selfplay.simulate(rounds=8, pop=100)
check("Autojuego (simulación) encarece la evasión",
      sim["cost_self"][-1] > sim["cost_static"][-1] * 1.5)

# Integración: la app arranca
check("La aplicación se construye", app.build_app() is not None)


# No se devuelven 403 (degradación silenciosa) a un humano
async def _noblock():
    r = await app.catch_all(make_mocked_request(
        "GET", "/pagina-inexistente",
        headers={"User-Agent": "mozilla", "X-Forwarded-For": "9.9.9.9"}))
    return r.status != 403
check("Nunca un 403 a un visitante normal", run(_noblock()))

# X-Forwarded-For solo se cree con un proxy de confianza delante
_req = make_mocked_request("GET", "/", headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
_prev = config.TRUST_PROXY
config.TRUST_PROXY = False
_ignored = app.client_ip(_req) not in ("1.2.3.4", "5.6.7.8")
config.TRUST_PROXY = True
_trusted = app.client_ip(_req) == "5.6.7.8"   # la que añadió el proxy
config.TRUST_PROXY = _prev
check("X-Forwarded-For solo se cree con proxy de confianza", _ignored and _trusted)

# Límites del laberinto: cupo por IP y total
lim = app.TarpitLimiter(total=3, per_ip=2)
_a = [lim.try_acquire("4.4.4.4") for _ in range(3)]
_b = [lim.try_acquire("4.4.4.5"), lim.try_acquire("4.4.4.6")]
lim.release("4.4.4.4")
_c = lim.try_acquire("4.4.4.6")
check("Cupo de conexiones del laberinto (por IP y total)",
      _a == [True, True, False] and _b == [True, False] and _c)


# Extremo a extremo: el goteo respeta su duración máxima y, sin cupo, el
# laberinto se sirve de golpe en vez de retener otra conexión
async def _tarpit_limits():
    prev = config.TARPIT_MAX_SECONDS, app.limiter
    config.TARPIT_MAX_SECONDS = 1
    app.limiter = app.TarpitLimiter(total=10, per_ip=1)
    # Etapa 3: entre trozos se esperan 6-14 s, así que sin el tope la página
    # tardaría minutos. Terminar en ~1 s solo se explica por el tope.
    classifier.get_visitor("127.0.0.1", "curl/8").stage = 3
    clock = time.monotonic   # el reloj de pared puede dar saltos (p. ej. en Docker)
    try:
        async with TestClient(TestServer(app.build_app())) as c:
            hdr = {"User-Agent": "curl/8"}
            t0 = clock()
            first = asyncio.ensure_future(c.get("/m/a", headers=hdr))
            await asyncio.sleep(0.3)               # la 1ª ya ocupa el cupo
            t1 = clock()
            r2 = await c.get("/m/b", headers=hdr)
            body2 = await r2.text()
            fast = clock() - t1
            r1 = await first
            body1 = await r1.text()
            slow = clock() - t0
            return (fast < 0.5 and "</html>" in body2 and
                    0.8 < slow < 3.0 and "</html>" in body1)
    finally:
        config.TARPIT_MAX_SECONDS, app.limiter = prev
check("Laberinto acotado: duración máxima y sin goteo al agotar el cupo",
      run(_tarpit_limits()))

print()
passed = sum(1 for ok, _ in results if ok)
print(f"RESULTADO: {passed}/{len(results)} comprobaciones superadas")
raise SystemExit(0 if passed == len(results) else 1)
