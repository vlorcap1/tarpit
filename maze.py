"""Generador del laberinto.

Cada render usa una semilla aleatoria distinta, por lo que el contenido,
la estructura HTML, el número de enlaces y las rutas cambian SIEMPRE.
El bot no puede aprender una firma estable ni detectar el patrón.

Las páginas se devuelven en "trozos" para enviarlas a goteo (drip-feed):
el servidor escribe un trozo, espera, escribe otro... y mantiene al bot
colgado de una respuesta que nunca termina rápido.
"""

import random
import string

import config

WORDS = (
    "tiempo persona año forma parte vida caso mundo estado momento manera "
    "trabajo historia punto hecho lugar mano agua ejemplo razon mujer hombre "
    "pais sistema programa pregunta gobierno numero grupo problema ciudad "
    "campo centro proyecto idea modelo nivel proceso servicio valor mercado "
    "cambio grado fuerza color cuerpo papel libro calle noche palabra familia "
    "nombre verdad orden paso efecto medida base sentido region camino fondo"
).split()

TEMPLATES = ("articulo", "foro", "directorio", "catalogo")


def _slug(rng, parts=None):
    parts = parts or rng.randint(2, 4)
    out = []
    for _ in range(parts):
        out.append("".join(rng.choice(string.ascii_lowercase)
                           for _ in range(rng.randint(3, 9))))
    return "-".join(out)


def _sentence(rng):
    words = [rng.choice(WORDS) for _ in range(rng.randint(6, 16))]
    s = " ".join(words)
    return s[:1].upper() + s[1:] + rng.choice([".", ".", ".", "?", "!"])


def _paragraph(rng):
    return " ".join(_sentence(rng) for _ in range(rng.randint(3, 7)))


def _links(rng, count):
    out = []
    for _ in range(count):
        depth = rng.randint(1, 4)
        path = config.MAZE_PREFIX + "/" + "/".join(_slug(rng) for _ in range(depth))
        if rng.random() < 0.4:  # a veces con query, a veces sin ella
            path += "?" + _slug(rng, 1) + "=" + str(rng.randint(1, 9999))
        text = " ".join(rng.choice(WORDS) for _ in range(rng.randint(2, 5))).title()
        out.append((path, text))
    return out


def stage_delay(stage):
    """Rango de espera (segundos) entre trozos. Sube con la etapa."""
    table = [(0.3, 0.9), (0.9, 2.5), (2.5, 6.0), (6.0, 14.0)]
    return table[min(stage, len(table) - 1)]


def trap_link(rng):
    """Enlace trampa único (va oculto en las páginas reales)."""
    return config.HONEYPOT_PREFIX + "/" + _slug(rng)


def render_page(seed, stage):
    """Devuelve una lista de trozos HTML. Única en cada llamada."""
    rng = random.Random(seed)
    tpl = rng.choice(TEMPLATES)
    title = " ".join(rng.choice(WORDS) for _ in range(rng.randint(3, 6))).title()
    n_paras = rng.randint(2, 4) + stage
    n_links = 6 + stage * 4

    links = _links(rng, n_links)
    paras = [_paragraph(rng) for _ in range(n_paras)]

    chunks = [
        f'<!doctype html><html lang="es"><head><meta charset="utf-8">'
        f'<title>{title}</title></head><body>',
        f'<h1>{title}</h1>',
    ]

    if tpl == "foro":
        for p in paras:
            chunks.append(f'<div class="post"><b>usuario{rng.randint(1, 999)}</b>'
                          f'<p>{p}</p></div>')
        chunks.append("<ul>")
        for href, txt in links:
            chunks.append(f'<li><a href="{href}">{txt}</a></li>')
        chunks.append("</ul>")

    elif tpl == "directorio":
        chunks.append("<nav><ul>")
        for href, txt in links:
            chunks.append(f'<li><a href="{href}">{txt}</a></li>')
        chunks.append("</ul></nav>")
        for p in paras:
            chunks.append(f"<p>{p}</p>")

    elif tpl == "catalogo":
        for href, txt in links:
            chunks.append(f'<section class="item"><h2><a href="{href}">{txt}</a></h2>'
                          f'<p>{_sentence(rng)}</p></section>')

    else:  # articulo
        for p in paras:
            chunks.append(f"<p>{p}</p>")
        chunks.append("<footer>")
        for href, txt in links:
            chunks.append(f'<a href="{href}">{txt}</a> ')
        chunks.append("</footer>")

    chunks.append("</body></html>")
    return chunks[:config.MAX_CHUNKS]
