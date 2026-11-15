# Configuración del tarpit
# -------------------------------------------------------------------
# En producción ponlo SIEMPRE detrás de un proxy inverso (nginx, Caddy)
# que pase la IP real en X-Forwarded-For.
import os

HOST = os.environ.get("TARPIT_HOST", "127.0.0.1")   # 0.0.0.0 en contenedor
PORT = int(os.environ.get("TARPIT_PORT", "8080"))

# Ruta trampa (honeypot). Va como Disallow en robots.txt
# y como enlace invisible en las páginas reales.
HONEYPOT_PREFIX = "/zona-restringida"

# Prefijo del laberinto. Todas las páginas falsas cuelgan de aquí.
MAZE_PREFIX = "/m"

# Secreto para firmar las rutas-cebo por IP (HMAC).
# En producción, ponlo en la variable de entorno TARPIT_SECRET.
import os
SECRET = os.environ.get("TARPIT_SECRET", "cambia-esto-por-un-secreto-largo-y-aleatorio")

# Nombres de cebo atractivos: lo primero que prueba un recolector.
BAIT_NAMES = [
    "panel-admin", "backup.sql", ".env", "wp-admin",
    "config.php.bak", "db-dump-2026.sql", "api/v1/users/export",
    "phpmyadmin", ".git/config", "internal/admin-tokens.json",
]

# Puntaje de sospecha (0 = humano / bot bueno, 100 = bot malo)
SCORE_SUSPICIOUS = 40   # a partir de aquí: vigilancia
SCORE_TARPIT = 60       # a partir de aquí: al laberinto

# Prueba de trabajo adaptativa: grava al bot con navegador real en la banda
# media de sospecha. Invisible para un humano (una página); ruinosa para una
# flota (millones). La dificultad sube con la sospecha.
POW_ON = True
POW_MIN_BITS = 14        # suave por defecto: cómodo incluso en móviles antiguos
POW_MAX_BITS = 18        # sube estos valores si recibes muchos bots sofisticados
POW_CHALLENGE_TTL = 120  # segundos de validez de un reto
POW_PASS_TTL = 300       # segundos que dura el pase tras resolverlo

# Instrumentación: exige señales de navegador real atadas a la prueba de trabajo,
# para que el reto no se pueda resolver con un cliente de terminal.
INSTRUMENT_ON = True
INSTRUMENT_FRAMES = 6    # nº de frames de render que debe reportar el cliente

# Asimetría de costes: respuesta comprimida servida SOLO a bots confirmados.
# ASYMMETRY_ON la activa; ASYMMETRY_MB es el tamaño descomprimido (acotado).
# Empieza desactivada: actívala a conciencia y revisa las advertencias.
ASYMMETRY_ON = False
ASYMMETRY_MB = 100     # MB que el bot descomprime; tú envías solo unos KB

# Degradación silenciosa: probabilidad de bot -> modo de respuesta.
# Nunca se devuelve 403; la experiencia empeora sin avisar.
GRAD_SLOW = 0.35      # desde aquí: contenido real pero lento
GRAD_TARPIT = 0.60    # desde aquí: al laberinto

# Control de ritmo
RATE_WINDOW = 10        # ventana en segundos
RATE_MAX = 30           # peticiones por ventana antes de penalizar

# Bots buenos verificables por DNS inverso.
# user-agent (en minúsculas) -> sufijos de dominio válidos
GOOD_BOTS = {
    "googlebot":   (".googlebot.com", ".google.com"),
    "bingbot":     (".search.msn.com",),
    "applebot":    (".applebot.apple.com",),
    "duckduckbot": (".duckduckgo.com",),
}

# User-agents de librerías/herramientas que casi nunca son humanos
SUSPICIOUS_UA = ("", "-", "python-requests", "curl", "wget",
                 "go-http-client", "scrapy", "httpclient")

# Memoria de visitantes
MAX_TRACKED_IPS = 50000
IP_TTL = 3600  # segundos sin actividad antes de olvidar una IP

# Tope de seguridad: máximo de trozos por respuesta del tarpit.
# Sube este número para laberintos "casi infinitos" (más coste para ti).
MAX_CHUNKS = 400
