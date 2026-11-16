"""Clasificación de visitantes por COMPORTAMIENTO.

La idea central: un bot malo puede falsificar su user-agent, pero no
puede falsificar lo que hace. Aquí medimos sus "movimientos":
  - ¿leyó robots.txt antes de entrar a zonas prohibidas?
  - ¿cayó en el enlace trampa invisible?
  - ¿a qué ritmo pide?
  - si dice ser Google/Bing, ¿lo confirma su DNS inverso?

Un "visitante" es la pareja (IP, user-agent), no la IP sola: detrás de una
misma IP puede haber muchas personas (oficinas, universidades, redes móviles
con CGNAT). Así, si un bot cae en la trampa, no arrastra al laberinto a todos
los que comparten su IP. El ritmo de peticiones, en cambio, se mide por IP,
para que un bot no lo esquive cambiando de user-agent en cada petición.
"""

import time
import socket
import hashlib
from collections import deque

import config


class Visitor:
    __slots__ = ("ip", "label", "first_seen", "last_seen", "hits", "timestamps",
                 "fetched_robots", "hit_honeypot", "claimed_bot",
                 "verified_good", "score", "stage", "bait_hits", "confirmed")

    def __init__(self, ip):
        now = time.time()
        self.ip = ip
        self.first_seen = now
        self.last_seen = now
        self.hits = 0
        self.timestamps = deque(maxlen=200)
        self.fetched_robots = False
        self.hit_honeypot = False
        self.claimed_bot = None        # nombre del bot que DICE ser
        self.verified_good = None      # None = sin comprobar; True/False tras DNS
        self.score = 0
        self.stage = 0
        self.bait_hits = 0             # cuántos cebos ha pisado (doble puerta)
        self.confirmed = False         # True = bot confirmado por 2ª puerta
        self.label = None              # etiqueta ya enviada al modelo (0/1)


_visitors = {}
_ip_times = {}   # ip -> deque de marcas de tiempo (ritmo por IP)


def _key(ip, ua):
    return ip + "|" + hashlib.sha256((ua or "").encode()).hexdigest()[:12]


def get_visitor(ip, ua=""):
    k = _key(ip, ua)
    v = _visitors.get(k)
    if v is None:
        v = Visitor(ip)
        _visitors[k] = v
        _maybe_prune()
    return v


def touch(v):
    now = time.time()
    v.last_seen = now
    v.timestamps.append(now)
    v.hits += 1
    q = _ip_times.get(v.ip)
    if q is None:
        q = _ip_times[v.ip] = deque(maxlen=500)
    q.append(now)


def _maybe_prune():
    if len(_visitors) <= config.MAX_TRACKED_IPS:
        return
    now = time.time()
    for k in [k for k, v in _visitors.items()
              if now - v.last_seen > config.IP_TTL]:
        _visitors.pop(k, None)
    # si aún está lleno, descarta el 10% más antiguo
    if len(_visitors) > config.MAX_TRACKED_IPS:
        oldest = sorted(_visitors.items(), key=lambda kv: kv[1].last_seen)
        for k, _ in oldest[:max(1, len(_visitors) // 10)]:
            _visitors.pop(k, None)
    for ip in [ip for ip, q in _ip_times.items()
               if not q or now - q[-1] > config.IP_TTL]:
        _ip_times.pop(ip, None)


def request_rate(v):
    """Peticiones recientes de este visitante (IP + user-agent)."""
    now = time.time()
    return sum(1 for t in v.timestamps if now - t <= config.RATE_WINDOW)


def ip_rate(ip):
    """Peticiones recientes de la IP, sumando todos sus user-agents."""
    now = time.time()
    return sum(1 for t in _ip_times.get(ip, ()) if now - t <= config.RATE_WINDOW)


# --- verificación de bots buenos (DNS inverso + confirmación directa) ---

def _reverse_forward(ip, domains):
    """Comprobación estándar: la IP debe resolver (DNS inverso) a un
    host del dominio esperado, y ese host debe resolver de vuelta a la
    misma IP. Un atacante no controla el DNS inverso de Google, así que
    no puede fingirlo."""
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return False
    if not any(host.endswith(d) for d in domains):
        return False
    try:
        forward = socket.gethostbyname_ex(host)[2]
    except Exception:
        return False
    return ip in forward


async def verify_good_bot(v, ua_lower, loop):
    """Devuelve True (verificado), False (impostor) o None (no dice serlo)."""
    if v.verified_good is not None or v.claimed_bot is not None:
        return v.verified_good
    for name, domains in config.GOOD_BOTS.items():
        if name in ua_lower:
            v.claimed_bot = name
            try:
                ok = await loop.run_in_executor(None, _reverse_forward, v.ip, domains)
            except Exception:
                ok = False
            v.verified_good = ok
            return ok
    return None


# --- puntaje de sospecha ---

def evaluate(v, path, ua_lower):
    score = 0

    # 1. Cayó en el honeypot invisible -> señal casi definitiva
    if v.hit_honeypot:
        score += 70

    # 2. Ignoró robots.txt: entró a zona prohibida sin leer las reglas
    if path.startswith(config.HONEYPOT_PREFIX) and not v.fetched_robots:
        score += 20

    # 3. Ritmo excesivo (por IP: cambiar de user-agent no lo esquiva)
    r = ip_rate(v.ip)
    if r > config.RATE_MAX:
        score += min(30, r - config.RATE_MAX)

    # 4. User-agent de herramienta/vacío
    if any(ua_lower == s or (s and s in ua_lower) for s in config.SUSPICIOUS_UA):
        score += 15

    # 5. Dice ser bot bueno pero el DNS lo desmiente (impostor)
    if v.claimed_bot and v.verified_good is False:
        score += 40

    v.score = min(100, score)
    return v.score
