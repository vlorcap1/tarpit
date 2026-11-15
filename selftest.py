"""Autodiagnóstico: comprueba que cada capa funciona. Ejecuta `python selftest.py`."""

import asyncio
import os

import config
import classifier
import bait
import learner
import pow
import instrument
import selfplay
import asymmetry
import app
from aiohttp.test_utils import make_mocked_request

OK, FAIL = "  ok ", "FAIL "
results = []


def check(name, cond):
    results.append((bool(cond), name))
    print(("[%s] " % (OK if cond else FAIL)) + name)


# Capa 1: cebos por IP, firmados, con detección de compartido
pa = bait.bait_paths("1.1.1.1")
pb = bait.bait_paths("2.2.2.2")
check("Cebos únicos por IP", set(pa).isdisjoint(pb))
check("Clasifica cebo propio", bait.classify("1.1.1.1", pa[0]) == "own")
check("Detecta cebo compartido", bait.classify("2.2.2.2", pa[0]) == "shared")

# Capa 2: el modelo aprende de etiquetas de la trampa
import time
from collections import deque

def _mk(bot):
    v = classifier.Visitor("x")
    now = time.time()
    v.timestamps = deque(now + i * (0.2 if bot else 3.0) for i in range(8))
    return v, ("curl" if bot else "mozilla/5.0"), (40 if bot else 3)

susp = config.SUSPICIOUS_UA
for _ in range(300):
    b = (_ % 2 == 0) if False else (os.urandom(1)[0] % 2 == 0)
    v, ua, rate = _mk(b)
    learner.learn(learner.features(v, rate, ua, susp), 1.0 if b else 0.0)
acc = 0
for _ in range(200):
    b = os.urandom(1)[0] % 2 == 0
    v, ua, rate = _mk(b)
    acc += (learner.predict(learner.features(v, rate, ua, susp)) > 0.5) == b
check("El modelo aprende (precisión > 85%)", acc / 200 > 0.85)

# Capa 4b: prueba de trabajo + instrumentación
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
    open("/tmp/_cli.js", "w").write(cli)
    sol = json.loads(subprocess.check_output(["node", "/tmp/_cli.js"]).decode())
    check("Navegador real resuelve el reto",
          pow.verify_solution(ip, chal, str(sol["n"]), sol["e"], sol["b"]))
    check("Cliente de terminal rechazado",
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

# Autojuego: coste de evadir sube frente a defensa estática
import random
random.seed(1)
sim = selfplay.simulate(rounds=8, pop=100)
check("Autojuego encarece la evasión",
      sim["cost_self"][-1] > sim["cost_static"][-1] * 1.5)

# Integración: la app arranca
check("La aplicación se construye", app.build_app() is not None)

# No se devuelven 403 (degradación silenciosa) a un humano
async def _noblock():
    r = await app.catch_all(make_mocked_request(
        "GET", "/pagina-inexistente",
        headers={"User-Agent": "mozilla", "X-Forwarded-For": "9.9.9.9"}))
    return r.status != 403
check("Nunca un 403 a un visitante normal",
      asyncio.new_event_loop().run_until_complete(_noblock()))

print()
passed = sum(1 for ok, _ in results if ok)
print(f"RESULTADO: {passed}/{len(results)} comprobaciones superadas")
raise SystemExit(0 if passed == len(results) else 1)
