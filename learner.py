"""Clasificador que APRENDE de las etiquetas que genera la propia trampa.

La trampa (honeypot) etiqueta "bot" con casi total certeza a quien cae.
Verificar un bot bueno por DNS, o una sesión con interacción humana clara,
etiqueta "humano". Con esas etiquetas entrenamos, en vivo, un modelo sobre
el COMPORTAMIENTO del visitante —sin usar "cayó en la trampa" como variable—
para que aprenda a reconocer el perfil de bot ANTES de que pise la trampa.

Es regresión logística en línea (SGD), sin dependencias externas, con pesos
persistidos en disco para sobrevivir a reinicios.
"""

import json
import math
import os

WEIGHTS_FILE = os.environ.get("TARPIT_WEIGHTS", "weights.json")

# Nombres de las variables de comportamiento (NO incluyen el honeypot).
FEATURES = ("rate", "ua_sospechoso", "bot_no_verificado",
            "leyo_robots", "regularidad")

_w = [0.0] * len(FEATURES)
_bias = 0.0
_lr = 0.2
_seen = 0


def _load():
    global _w, _bias, _seen
    try:
        with open(WEIGHTS_FILE) as f:
            d = json.load(f)
        if len(d.get("w", [])) == len(FEATURES):
            _w = d["w"]
            _bias = d["bias"]
            _seen = d.get("seen", 0)
    except Exception:
        pass


def _save():
    try:
        with open(WEIGHTS_FILE, "w") as f:
            json.dump({"w": _w, "bias": _bias, "seen": _seen}, f)
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


MIN_SEEN = 50  # hasta tener esta cantidad de etiquetas, no se confía en el modelo


def ready():
    return _seen >= MIN_SEEN


def predict(x):
    """Probabilidad aprendida de que el visitante sea un bot (0..1).
    Devuelve 0 mientras el modelo no haya aprendido lo suficiente, para
    no arrastrar a humanos por un modelo inmaduro (manda el motor de reglas)."""
    if not ready():
        return 0.0
    z = _bias + sum(w * xi for w, xi in zip(_w, x))
    return _sigmoid(z)


def learn(x, y):
    """Actualiza el modelo con una etiqueta de verdad: y=1 bot, y=0 humano."""
    global _bias, _seen
    p = predict(x)
    err = p - y
    for i in range(len(_w)):
        _w[i] -= _lr * err * x[i]
    _bias -= _lr * err
    _seen += 1
    if _seen % 20 == 0:
        _save()


def stats():
    return {"seen": _seen, "bias": round(_bias, 3),
            "weights": {n: round(w, 3) for n, w in zip(FEATURES, _w)}}


_load()
