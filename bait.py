"""Lógica de los cebos (honeypot) de robots.txt.

Combina tres ideas para hacerlos más tramposos:
  #1 Nombres jugosos: rutas que todo recolector quiere probar.
  #5 Rotativas por IP y firmadas: cada visitante ve rutas-cebo distintas,
     derivadas de su IP con HMAC. Así un bot no puede memorizar una lista
     negra de "paths honeypot" ni compartirla con otros bots.
  (La doble puerta #3 se arma en app.py sobre estas rutas.)
"""

import hmac
import hashlib
import random

import config


def _token(ip):
    """Firma corta e irreproducible de la IP. El atacante no conoce SECRET,
    así que no puede fabricar un token válido para su propia IP."""
    return hmac.new(config.SECRET.encode(), ip.encode(),
                    hashlib.sha256).hexdigest()[:12]


def bait_paths(ip):
    """Rutas-cebo únicas y estables para esta IP (van en su robots.txt)."""
    tok = _token(ip)
    rng = random.Random(ip)                       # mismas rutas por IP
    names = rng.sample(config.BAIT_NAMES, k=min(3, len(config.BAIT_NAMES)))
    return [f"{config.HONEYPOT_PREFIX}/{n}-{tok}" for n in names]


def classify(ip, path):
    """¿El path pedido es un cebo? Devuelve:
        'own'    -> cebo válido para ESTA IP: leyó su robots.txt y lo violó.
        'shared' -> cebo con token de OTRA IP: lo obtuvo de un tercero
                    (bots compartiendo inteligencia). Señal aún más fuerte.
        None     -> no es un cebo.
    """
    if not path.startswith(config.HONEYPOT_PREFIX):
        return None
    if path.endswith("-" + _token(ip)):
        return "own"
    tail = path.rsplit("-", 1)[-1]
    if len(tail) == 12 and all(c in "0123456789abcdef" for c in tail):
        return "shared"                            # token hex ajeno
    return "own"                                    # prefijo honeypot sin token
