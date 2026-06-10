PROYECTO FINAL IA - SENTINELMAIL AI

Tema:
Sistema inteligente para deteccion de phishing en correos electronicos y URLs.

Arquitectura:
El sistema esta organizado bajo Clean Architecture:
- Dominio: entidades y politicas de clasificacion.
- Aplicacion: caso de uso de analisis.
- Infraestructura: dataset, extractor de caracteristicas y algoritmos de IA.
- Presentacion: servidor web, plantilla, CSS y JavaScript.

Tecnicas de inteligencia artificial implementadas:
1. Red neuronal artificial feedforward con retropropagacion manual.
2. Clasificador Naive Bayes multinomial manual.
3. Sistema experto basado en reglas de ciberseguridad.

Estructura:
- codigo/app.py: aplicacion web local.
- codigo/src/phishing_detector/domain/: entidades, puertos y politicas.
- codigo/src/phishing_detector/application/: casos de uso.
- codigo/src/phishing_detector/infrastructure/: IA manual, datos y bootstrap.
- codigo/src/phishing_detector/presentation/web/: interfaz web profesional.
- codigo/tests/: pruebas de humo.
- documentacion/: espacio para el informe final en PDF.
- presentacion/: espacio para las diapositivas de defensa.

Requisitos:
- Python 3.10 o superior.
- No requiere instalar bibliotecas externas.

Ejecucion:
1. Abrir una terminal en la carpeta del proyecto.
2. Ejecutar:
   python codigo/app.py
3. Abrir en el navegador:
   http://127.0.0.1:8000

Pruebas:
Ejecutar:
   python -m unittest discover codigo/tests

Uso:
1. Escriba o pegue el asunto del correo.
2. Ingrese la URL principal que desea analizar.
3. Opcionalmente complete From, Reply-To, Return-Path y Authentication-Results.
4. Pegue el contenido del mensaje o cargue un archivo .eml.
5. Presione "Analizar riesgo".
6. Tambien puede agregar indicadores propios con nombre, categoria, patron regex y peso.
7. El sistema mostrara:
   - decision final,
   - porcentaje de riesgo,
   - salida de la red neuronal,
   - salida de Naive Bayes,
   - puntaje del sistema experto,
   - reglas activadas,
   - resumen de cabeceras,
   - cantidad de enlaces,
   - adjuntos detectados,
   - indicadores coincidentes.

Ejemplos incluidos:
- http://127.0.0.1:8000/sample/phishing
- http://127.0.0.1:8000/sample/legit
- http://127.0.0.1:8000/sample-eml/phishing-completo
- codigo/data/samples/phishing_demo.eml
- codigo/data/samples/phishing_completo_banco.eml
- codigo/data/samples/legit_demo.eml

Endpoint JSON:
Tambien se puede consultar con POST a:
http://127.0.0.1:8000/api/analyze

Nota academica:
El sistema usa datos simulados realistas para fines educativos. No debe utilizarse como
herramienta unica de seguridad en entornos reales.
