# Cómo colaborar

Telaraña quiere ser útil sobre todo a sitios pequeños —blogs, wikis, archivos,
ONG, proyectos de software libre— que hoy no tienen defensa contra el scraping
abusivo. Toda ayuda en esa dirección es bienvenida.

## Formas de ayudar que no son código

- **Documentación clara.** Si algo no se entendió, arréglalo. Es lo más valioso.
- **Traducciones** del README y de las guías.
- **Probar la instalación** en distintos sistemas y reportar qué falló.
- **Casos de uso reales** y ajustes de `GOOD_BOTS` para rastreadores legítimos.

## Colaborar con código

1. Abre un issue describiendo el problema o la idea antes de un cambio grande.
2. Mantén el estilo: sin dependencias pesadas, módulos pequeños y comentados.
3. **Toda capa nueva necesita una comprobación en `selftest.py`.** Si no se
   puede verificar, no entra.
4. Ejecuta `python selftest.py` antes de proponer cambios: deben pasar
   todas (`RESULTADO: N/N`).

## Principios del proyecto

- **Defender sin dañar la web abierta.** Ante la duda, el valor por defecto más
  prudente. Respetar a los bots buenos no es opcional.
- **Honestidad sobre los límites.** Nada de prometer detección perfecta. Si una
  capa solo sube el coste de evadir, se dice así.
- **Desplegable por no expertos.** Una función brillante que nadie sabe instalar
  no ayuda a nadie.

## Reportar vulnerabilidades

Si encuentras un fallo de seguridad en Telaraña, **no lo publiques**: repórtalo
de forma privada al mantenedor para que pueda arreglarse antes de divulgarlo.

## Lo que este proyecto NO quiere ser

Una herramienta ofensiva, un arma, o algo que castigue a investigadores,
archivistas o buscadores legítimos. Las contribuciones en esa dirección se
rechazarán. Ver `RESPONSIBLE_USE.md`.
