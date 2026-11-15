"""Defensa por autojuego adversarial.

Bucle tipo GAN local: un ADVERSARIO evoluciona para evadir a la defensa actual,
y la DEFENSA se reentrena con los intentos de evasión que captura (gracias a las
etiquetas de verdad del honeypot y la atribución). Ambos coevolucionan.

Tesis (honesta): no se consigue detección perfecta —imposible contra un
adversario que puede imitar cualquier señal—, sino que se MAXIMIZA EL COSTE DE
EVADIR. Cada señal barata que el bot aprende a fingir, la defensa deja de
valorarla y se apoya en las que aún no finge; eso empuja al bot a fingir también
las caras (ejecutar un navegador real, un motor de JS), hasta el coste máximo.

Aquí va la simulación que lo demuestra y una función para endurecer el modelo
real de learner.py mediante entrenamiento adversarial.
"""

import random
import math

# Señales de comportamiento (1 = muy de bot). Para cada una, cuánto CUESTA
# fingirla (bajar su valor hacia "humano"). Las dos últimas son caras porque
# exigen un navegador y un motor de JS reales.
FEATURES = ["ritmo", "ua_sospechoso", "regularidad", "sin_navegador", "sin_js"]
FAKE_COST = [1.0, 0.5, 1.5, 4.0, 3.0]


def _sigmoid(z):
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class Model:
    def __init__(self, n):
        self.w = [0.0] * n
        self.b = 0.0

    def predict(self, x):
        return _sigmoid(self.b + sum(wi * xi for wi, xi in zip(self.w, x)))

    def fit(self, X, y, epochs=60, lr=0.3):
        for _ in range(epochs):
            idx = list(range(len(X)))
            random.shuffle(idx)
            for i in idx:
                p = self.predict(X[i])
                err = p - y[i]
                for j in range(len(self.w)):
                    self.w[j] -= lr * err * X[i][j]
                self.b -= lr * err


def human():
    return [max(0.0, min(1.0, random.gauss(0.1, 0.08))) for _ in FEATURES]


def bot():
    return [max(0.0, min(1.0, random.gauss(0.9, 0.08))) for _ in FEATURES]


def evade(model, b, threshold=0.5):
    """El adversario baja, de la más rentable a la menos, las señales que más
    lo delatan por unidad de coste, hasta cruzar el umbral o agotar opciones.
    Devuelve (vector_evadido, coste, evadio?)."""
    x = b[:]
    cost = 0.0
    order = sorted(range(len(FEATURES)),
                   key=lambda i: model.w[i] / FAKE_COST[i], reverse=True)
    for i in order:
        while model.predict(x) >= threshold and x[i] > 0.0:
            step = min(0.1, x[i])
            x[i] -= step
            cost += step * FAKE_COST[i]
        if model.predict(x) < threshold:
            break
    return x, cost, model.predict(x) < threshold


def simulate(rounds=12, pop=120, budget=3.0):
    """Compara una defensa ESTÁTICA con una de AUTOJUEGO frente a un adversario
    que evoluciona cada ronda. Devuelve series para graficar."""
    n = len(FEATURES)
    X = [human() for _ in range(200)] + [bot() for _ in range(200)]
    y = [0.0] * 200 + [1.0] * 200

    static = Model(n); static.fit(X, y)
    selfp = Model(n); selfp.fit(X, y)
    dX, dY = X[:], y[:]

    cost_static, cost_self = [], []
    ev_static, ev_self = [], []

    for _ in range(rounds):
        bots = [bot() for _ in range(pop)]

        rs = [evade(static, b) for b in bots]
        rp = [evade(selfp, b) for b in bots]

        cost_static.append(sum(c for _, c, _ in rs) / pop)
        cost_self.append(sum(c for _, c, _ in rp) / pop)
        # evasión bajo PRESUPUESTO: el atacante solo evade si le sale a cuenta
        ev_static.append(sum(1 for _, c, e in rs if e and c <= budget) / pop)
        ev_self.append(sum(1 for _, c, e in rp if e and c <= budget) / pop)

        # AUTOJUEGO: las evasiones capturadas son negativos difíciles (etiqueta
        # bot, vía honeypot/atribución). La defensa se reentrena con ellas.
        hardX = [x for x, _, _ in rp]
        dX += hardX + [human() for _ in range(40)]
        dY += [1.0] * len(hardX) + [0.0] * 40
        selfp = Model(n); selfp.fit(dX, dY)

    return {"cost_static": cost_static, "cost_self": cost_self,
            "ev_static": ev_static, "ev_self": ev_self}


def harden(fit_fn, rounds=10):
    """Endurece un modelo real: genera adversarios que lo evaden, los añade como
    negativos difíciles y reentrena. fit_fn(X, y) entrena el modelo objetivo.
    (Gancho para conectar con learner.py en producción.)"""
    n = len(FEATURES)
    X = [human() for _ in range(200)] + [bot() for _ in range(200)]
    y = [0.0] * 200 + [1.0] * 200
    m = Model(n); m.fit(X, y)
    for _ in range(rounds):
        evaded = [evade(m, bot())[0] for _ in range(100)]
        X += evaded + [human() for _ in range(40)]
        y += [1.0] * len(evaded) + [0.0] * 40
        m = Model(n); m.fit(X, y)
    fit_fn(X, y)
    return m
