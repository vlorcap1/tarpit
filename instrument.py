"""Capa de instrumentación sobre la prueba de trabajo.

El fallo de un PoW puro (lo que tumbó a Anubis) es que un cliente de terminal
puede calcular el hash de forma nativa, sin navegador, y repartir ese coste
entre millones de peticiones. La instrumentación lo cierra: exige que la
solución venga acompañada de señales que solo produce un navegador de verdad
(canvas, propiedades de navigator, un bucle de render con requestAnimationFrame)
y ata esas señales al cálculo del hash. Para generarlas, el atacante ya no puede
usar un bucle de hashes nativo: tiene que incrustar un navegador completo, que
es justo el coste que queremos imponerle.

Verdad honesta: las señales de cliente siempre son, en teoría, falsificables.
El objetivo no es volverlas infalsificables, sino **subir el coste** de evadir
desde "trivial" (anubis-fetch) hasta "ejecutar un navegador real". A ese bot,
ya en el nivel caro, lo recogen las otras capas (comportamiento y aprendizaje).
"""

import re

import config

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def parse_bundle(b):
    """El paquete viaja como 'k=v;k=v;...'. Lo devolvemos como dict."""
    out = {}
    for part in b.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def verify(fields):
    """True si el paquete de señales parece un navegador real y coherente."""
    try:
        # 1. Sin bandera de automatización declarada
        if fields.get("wd", "1") != "0":
            return False
        # 2. Idiomas presentes (un runtime pelado no los tiene)
        if int(fields.get("langs", "0")) < 1 or not fields.get("lang", ""):
            return False
        # 3. Pantalla plausible (existe un entorno gráfico)
        sw, sh = int(fields.get("sw", "0")), int(fields.get("sh", "0"))
        if not (320 <= sw <= 8192 and 320 <= sh <= 8192):
            return False
        # 4. Densidad de píxeles realista (0.5x a 4x, guardada x100)
        if not (50 <= int(fields.get("dpr", "0")) <= 400):
            return False
        # 5. Huella de canvas: requiere un motor de render; hex de 64 y no trivial
        cv = fields.get("cv", "")
        if not _HEX64.match(cv) or len(set(cv)) < 4:
            return False
        # 6. Bucle de render: deltas de varios frames, con jitter (no idénticos)
        frames = [int(x) for x in fields.get("frames", "").split(",") if x != ""]
        if len(frames) < config.INSTRUMENT_FRAMES:
            return False
        if any(d < 1 or d > 200 for d in frames):
            return False
        if len(set(frames)) < 2:          # un emulador perezoso pone todos iguales
            return False
        return True
    except (ValueError, TypeError):
        return False
