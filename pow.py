"""Prueba de trabajo (proof-of-work) adaptativa.

Grava al adversario que ninguna trampa de enlaces caza: el navegador headless
que renderiza y ejecuta JS. El cliente debe encontrar un 'nonce' tal que
SHA-256(reto + nonce) tenga N bits iniciales en cero. La dificultad N sube con
la sospecha. Para un humano con una página es imperceptible; para una flota que
pide millones, el coste de CPU se vuelve ruinoso. Y como la dificultad es
continua, el bot no tiene un umbral binario contra el que optimizar.

Sin estado en el servidor: el reto se firma con HMAC y lleva su marca de tiempo
y su dificultad dentro, así que se verifica sin guardar nada. Tras resolverlo,
se emite un 'pase' firmado de corta duración para que un humano no repita el
cálculo en cada página.
"""

import os
import time
import hmac
import hashlib

import config
import instrument


def _sig(parts):
    return hmac.new(config.SECRET.encode(), ":".join(parts).encode(),
                    hashlib.sha256).hexdigest()[:16]


def difficulty_for(suspicion):
    """Mapea la sospecha (en la banda media) a bits de dificultad."""
    lo, hi = config.GRAD_SLOW, config.GRAD_TARPIT
    t = 0.0 if hi <= lo else max(0.0, min(1.0, (suspicion - lo) / (hi - lo)))
    span = config.POW_MAX_BITS - config.POW_MIN_BITS
    return config.POW_MIN_BITS + int(round(t * span))


def make_challenge(ip, difficulty):
    ts = str(int(time.time()))
    rand = os.urandom(8).hex()
    diff = str(difficulty)
    sig = _sig([ts, rand, diff, ip])
    return f"{ts}:{rand}:{diff}:{sig}"


def _leading_zero_bits(digest_bytes):
    n = 0
    for byte in digest_bytes:
        if byte == 0:
            n += 8
            continue
        for b in range(7, -1, -1):
            if byte & (1 << b):
                return n
            n += 1
        return n
    return n


def verify_solution(ip, challenge, nonce, env=None, bundle=None):
    """True si el reto es legítimo y fresco, el nonce lo resuelve y —si la
    instrumentación está activa— la solución está atada a un navegador real."""
    try:
        ts, rand, diff, sig = challenge.split(":")
        difficulty = int(diff)
    except Exception:
        return False
    if _sig([ts, rand, diff, ip]) != sig:          # ¿lo emitimos para esta IP?
        return False
    if time.time() - int(ts) > config.POW_CHALLENGE_TTL:   # ¿sigue fresco?
        return False

    if config.INSTRUMENT_ON:
        if not env or not bundle:
            return False
        # el entorno debe corresponder al paquete enviado (no se puede sustituir)
        if hashlib.sha256(bundle.encode()).hexdigest() != env:
            return False
        if not instrument.verify(instrument.parse_bundle(bundle)):
            return False
        # el trabajo está atado al entorno: hash(reto:entorno:nonce)
        material = challenge + ":" + env + ":" + nonce
    else:
        material = challenge + ":" + nonce

    digest = hashlib.sha256(material.encode()).digest()
    return _leading_zero_bits(digest) >= difficulty


def issue_pass(ip):
    exp = str(int(time.time()) + config.POW_PASS_TTL)
    return f"{exp}:{_sig(['pass', ip, exp])}"


def check_pass(ip, cookie):
    if not cookie:
        return False
    try:
        exp, sig = cookie.split(":")
    except Exception:
        return False
    if _sig(["pass", ip, exp]) != sig:
        return False
    return int(exp) > time.time()


def challenge_page(path, challenge, difficulty):
    """Página que recoge señales de navegador real, las ata al reto y lo
    resuelve en el cliente. Incluye una SHA-256 síncrona rápida."""
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<title>Un momento…</title></head><body>'
        '<p>Verificando tu navegador…</p>'
        '<script>' + _SHA256_JS +
        'var C=' + _js_str(challenge) + ',D=' + str(difficulty) +
        ',P=' + _js_str(path) + ',NF=' + str(config.INSTRUMENT_FRAMES) + ';'
        'function zeros(h){var n=0;for(var i=0;i<h.length;i++){'
        'var v=parseInt(h[i],16);if(v===0){n+=4;continue;}'
        'if(v<2)return n+3;if(v<4)return n+2;if(v<8)return n+1;return n;}return n;}'
        # huella de canvas: requiere un motor de render real
        'function canvasFP(){try{var c=document.createElement("canvas");c.width=200;'
        'c.height=40;var x=c.getContext("2d");x.textBaseline="top";x.font="14px Arial";'
        'x.fillStyle="#069";x.fillText("inst-"+navigator.userAgent.slice(0,18),2,2);'
        'x.fillStyle="rgba(255,0,0,0.5)";x.fillRect(5,5,60,20);'
        'return sha256(c.toDataURL());}catch(e){return sha256("nocanvas");}}'
        # recoge NF frames de render (bucle real) y luego resuelve
        'var frames=[],last=performance.now();'
        'function tick(){var t=performance.now();var d=Math.max(1,Math.round(t-last));'
        'last=t;frames.push(d);if(frames.length<NF){requestAnimationFrame(tick);}else{solve();}}'
        'function solve(){'
        'var b="wd="+(navigator.webdriver?1:0)+";lang="+(navigator.language||"")'
        '+";langs="+((navigator.languages||[]).length)+";plugins="+((navigator.plugins||[]).length)'
        '+";sw="+screen.width+";sh="+screen.height+";dpr="+Math.round((devicePixelRatio||1)*100)'
        '+";hc="+(navigator.hardwareConcurrency||0)+";cv="+canvasFP()+";frames="+frames.join(",");'
        'var E=sha256(b);'
        'var k=0;while(true){if(zeros(sha256(C+":"+E+":"+k))>=D)break;k++;}'
        'location.href=P+(P.indexOf("?")<0?"?":"&")+"c="+encodeURIComponent(C)'
        '+"&n="+k+"&e="+E+"&b="+encodeURIComponent(b);}'
        'requestAnimationFrame(tick);'
        '</script></body></html>'
    )


def _js_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# SHA-256 síncrona, correcta y sin estado entre llamadas. sha256(str)->hex.
_SHA256_JS = r"""
var sha256=(function(){
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function rotr(x,n){return (x>>>n)|(x<<(32-n));}
function hx(n){var s='';for(var i=7;i>=0;i--)s+=((n>>>(i*4))&0xf).toString(16);return s;}
return function(msg){
var bytes=[],i;
for(i=0;i<msg.length;i++){var c=msg.charCodeAt(i);
if(c<128)bytes.push(c);
else if(c<2048)bytes.push(192|(c>>6),128|(c&63));
else bytes.push(224|(c>>12),128|((c>>6)&63),128|(c&63));}
var l=bytes.length;bytes.push(0x80);
while(bytes.length%64!==56)bytes.push(0);
var bl=l*8;bytes.push(0,0,0,0,(bl>>>24)&255,(bl>>>16)&255,(bl>>>8)&255,bl&255);
var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
for(var o=0;o<bytes.length;o+=64){
var w=new Array(64);
for(i=0;i<16;i++)w[i]=(bytes[o+i*4]<<24)|(bytes[o+i*4+1]<<16)|(bytes[o+i*4+2]<<8)|(bytes[o+i*4+3]);
for(i=16;i<64;i++){var x=w[i-15],y=w[i-2];
var s0=rotr(x,7)^rotr(x,18)^(x>>>3),s1=rotr(y,17)^rotr(y,19)^(y>>>10);
w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}
var a=H[0],b=H[1],c2=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
for(i=0;i<64;i++){
var S1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^(~e&g);
var t1=(h+S1+ch+K[i]+w[i])|0;
var S0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&c2)^(b&c2);
var t2=(S0+maj)|0;
h=g;g=f;f=e;e=(d+t1)|0;d=c2;c2=b;b=a;a=(t1+t2)|0;}
H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c2)|0;H[3]=(H[3]+d)|0;
H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;}
var out='';for(i=0;i<8;i++)out+=hx(H[i]);return out;};
})();
"""
