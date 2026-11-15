"""Clasificador que APRENDE de las etiquetas que genera la propia trampa.

Etiquetas:
  - "bot"    (y=1): el visitante pisó un cebo de robots.txt.
  - "humano" (y=0): bot bueno verificado por DNS, o visitante que resolvió la
                    prueba de trabajo con señales de navegador y nunca pisó un
                    cebo.

Con esas etiquetas entrenamos, en vivo, un modelo sobre el COMPORTAMIENTO del
visitante —sin usar "cayó en la trampa" como variable— para que aprenda a
reconocer el perfil de bot ANTES de que pise la trampa.

Salvaguardas contra falsos positivos:
  - Equilibrio de clases: en un sitio pequeño casi todas las etiquetas son
    "bot". Si se entrenara con ellas tal cual, el modelo aprendería que TODO
    visitante es un bot. Por eso se guardan ejemplos de ambas clases y cada
    paso de aprendizaje usa un ejemplo de cada una.
  - No se activa hasta tener MIN_PER_CLASS ejemplos de CADA clase. Sin
    ejemplos de humanos, el modelo no opina (manda el motor de reglas).
  - Su poder está acotado en app.py: el modelo solo puede pedir la prueba de
    trabajo, nunca mandar a nadie al laberinto.

Es regresión logística en línea (SGD), sin dependencias externas, con pesos y
ejemplos persistidos en disco para sobrevivir a reinicios.
"""

import json
import math
import os
import random
from collections import deque

WEIGHTS_FILE = os.environ.get("TARPIT_WEIGHTS", "weights.json")
_FORMAT = 2   # versión del archivo; los pesos del formato antiguo se descartan

# Nombres de las variables de comportamiento (NO incluyen el honeypot).
FEATURES = ("rate", "ua_sospechoso", "bot_no_verificado",
            "leyo_robots", "regularidad")

BUFFER = 500          # ejemplos guardados por clase
MIN_PER_CLASS = 25    # ejemplos mínimos de CADA clase antes de opinar
_LR = 0.2
_L2 = 0.001           # regularización: evita pesos desbocados

_w = [0.0] * len(FEATURES)
_bias = 0.0
_seen = 0
_pos = deque(maxlen=BUFFER)   # ejemplos de bot
_neg = deque(maxlen=BUFFER)   # ejemplos de humano


def reset():
    """Vacía el modelo (útil en pruebas)."""
    global _w, _bias, _seen
    _w = [0.0] * len(FEATURES)
    _bias = 0.0
    _seen = 0
    _pos.clear()
    _neg.clear()


def _load():
    global _w, _bias, _seen
    try:
        with open(WEIGHTS_FILE) as f:
            d = json.load(f)
    except Exception:
        return
    if d.get("format") != _FORMAT or len(d.get("w", [])) != len(FEATURES):
        return   # formato antiguo (posiblemente sesgado): se empieza de cero
    _w = [float(x) for x in d["w"]]
    _bias = float(d["bias"])
    _seen = int(d.get("seen", 0))
    _pos.extend(d.get("pos", []))
    _neg.extend(d.get("neg", []))


def _save():
    try:
        with open(WEIGHTS_FILE, "w") as f:
            json.dump({"format": _FORMAT, "w": _w, "bias": _bias,
                       "seen": _seen, "pos": list(_pos), "neg": list(_neg)}, f)
    except Exception:
        pass


def _sigmoid(z):
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def features(v, rate, ua_lower, suspicious_ua):
    """Vector de comportamiento en [0,1]. No usa hit_honeypot (eso es etiqueta)."""
    ts = list(v.timestamps)
    if len(ts) >= 3:
        deltas = [b - a for a, b in zip(ts, ts[1:])]
        mean = sum(deltas) / len(deltas)
        var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        std = var ** 0.5
        regularidad = 1.0 / (1.0 + std)   # poca varianza entre peticiones -> bot
    else:
        regularidad = 0.0
    ua_susp = 1.0 if any(ua_lower == s or (s and s in ua_lower)
                         for s in suspicious_ua) else 0.0
    return [
        min(rate / 30.0, 1.0),
        ua_susp,
        1.0 if (v.claimed_bot and v.verified_good is False) else 0.0,
        1.0 if v.fetched_robots else 0.0,
        regularidad,
    ]


def ready():
    return len(_pos) >= MIN_PER_CLASS and len(_neg) >= MIN_PER_CLASS


def _raw(x):
    return _sigmoid(_bias + sum(w * xi for w, xi in zip(_w, x)))


def predict(x):
    """Probabilidad aprendida de que el visitante sea un bot (0..1).
    Devuelve 0 mientras el modelo no tenga suficientes ejemplos de AMBAS
    clases, para no arrastrar a humanos por un modelo inmaduro."""
    if not ready():
        return 0.0
    return _raw(x)


def _step(x, y):
    global _bias
    err = _raw(x) - y
    for i in range(len(_w)):
        _w[i] -= _LR * (err * x[i] + _L2 * _w[i])
    _bias -= _LR * err


def learn(x, y):
    """Registra una etiqueta de verdad (y=1 bot, y=0 humano) y entrena con un
    ejemplo de cada clase, para que el desequilibrio no sesgue el modelo."""
    global _seen
    x = [float(v) for v in x]
    is_bot = y >= 0.5
    (_pos if is_bot else _neg).append(x)
    _seen += 1
    if _pos and _neg:   # sin ejemplos de ambas clases no se entrena
        _step(x, 1.0 if is_bot else 0.0)
        _step(random.choice(_neg if is_bot else _pos), 0.0 if is_bot else 1.0)
    if _seen % 20 == 0:
        _save()


def stats():
    return {"seen": _seen, "bots": len(_pos), "humanos": len(_neg),
            "listo": ready(), "bias": round(_bias, 3),
            "weights": {n: round(w, 3) for n, w in zip(FEATURES, _w)}}


_load()
