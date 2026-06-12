PROYECTO FINAL IA - SENTINELMAIL AI

Tema:
Sistema inteligente para detección de phishing en correos electrónicos y URLs.

Arquitectura:
El sistema está organizado bajo Clean Architecture:
- Dominio: entidades y políticas de clasificación.
- Aplicación: caso de uso de análisis.
- Infraestructura: datasets, extractor de características, algoritmos de IA, historial y reportes.
- Presentación: servidor web, plantilla, CSS y JavaScript.

Técnicas de inteligencia artificial implementadas:
1. Red neuronal artificial feedforward con retropropagación manual.
2. Clasificador Naive Bayes multinomial manual.
3. Árbol de decisión manual basado en impureza Gini.
4. Sistema experto basado en reglas de ciberseguridad.

Mejoras incluidas:
- Carga automática de datasets externos reales en CSV, JSON, JSONL o EML desde codigo/data/datasets.
- Separación entre entrenamiento y prueba para reportar exactitud de validación.
- Historial local de análisis en codigo/data/history/analysis_history.json.
- Exportación de reportes PDF en codigo/data/reports.
- Análisis interno de adjuntos: SHA-256, extensiones peligrosas, doble extensión y sospecha de macros.
- Textos visibles corregidos con tildes y ñ.

Estructura:
- codigo/app.py: aplicación web local.
- codigo/src/phishing_detector/domain/: entidades, puertos y políticas.
- codigo/src/phishing_detector/application/: casos de uso.
- codigo/src/phishing_detector/infrastructure/: IA manual, datos, parser, historial y reportes.
- codigo/src/phishing_detector/presentation/web/: interfaz web profesional.
- codigo/data/datasets/: ubicación para datasets públicos reales.
- codigo/tests/: pruebas de humo.
- documentacion/: espacio para el informe final.

Requisitos:
- Python 3.10 o superior.
- No requiere instalar bibliotecas externas.

Ejecución:
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
6. También puede agregar indicadores propios con nombre, categoría, patrón regex y peso.
7. El sistema mostrará:
   - decisión final,
   - porcentaje de riesgo,
   - salida de la red neuronal,
   - salida de Naive Bayes,
   - salida del árbol de decisión,
   - puntaje del sistema experto,
   - reglas activadas,
   - resumen de cabeceras,
   - cantidad de enlaces,
   - adjuntos detectados,
   - indicadores coincidentes,
   - enlace a reporte PDF,
   - historial de análisis.

Ejemplos incluidos:
- http://127.0.0.1:8000/sample/phishing
- http://127.0.0.1:8000/sample/legit
- http://127.0.0.1:8000/sample-eml/phishing-completo
- codigo/data/samples/phishing_demo.eml
- codigo/data/samples/phishing_completo_banco.eml
- codigo/data/samples/legit_demo.eml

Endpoint JSON:
También se puede consultar con POST a:
http://127.0.0.1:8000/api/analyze

Nota académica:
El sistema puede cargar datasets reales externos, pero no incluye correos maliciosos reales dentro del repositorio para evitar distribuir enlaces o adjuntos peligrosos. Si no hay datasets externos, utiliza datos simulados realistas para fines educativos. No debe utilizarse como herramienta única de seguridad en entornos reales.
