"""Asimetría de costes.

A un bot CONFIRMADO se le sirve una respuesta diminuta en la red pero que,
al descomprimirse, ocupa mucho en su memoria/CPU. Tú envías unos KB; su
parser procesa cientos de MB. Combinado con el goteo asíncrono, el atacante
paga caro mientras tú apenas gastas.

Responsable por diseño:
  - Acotado: el tamaño descomprimido tiene un tope configurable (no es un
    arma para tumbar una máquina, es un impuesto que encarece el scraping).
  - Selectivo: solo para visitantes 'confirmed', nunca para un dudoso.
  - Honesto en la cabecera: se declara Content-Encoding: gzip. Un cliente
    bien hecho que respeta límites de descompresión no se ve afectado; el
    que descomprime a ciegas todo lo que recibe —típico de un scraper
    agresivo— es quien paga.
"""

import gzip

import config


def _build(decompressed_mb):
    # Patrón muy corto y repetitivo => se acerca al máximo de compresión
    # (~1000:1). Sigue siendo HTML válido para que parezca contenido real.
    unit = b"<p>x</p>"
    target = decompressed_mb * 1024 * 1024
    reps = max(1, target // len(unit))
    body = (b"<!doctype html><title>Resultados</title>" + unit * reps)
    return gzip.compress(body, compresslevel=9)


# Se construye una sola vez al arrancar (coste único, se reutiliza en memoria).
_PAYLOAD = None


def payload():
    global _PAYLOAD
    if _PAYLOAD is None:
        _PAYLOAD = _build(config.ASYMMETRY_MB)
    return _PAYLOAD


def ratio():
    """Devuelve (bytes_enviados, MB_descomprimidos) para registro/depuración."""
    return len(payload()), config.ASYMMETRY_MB
