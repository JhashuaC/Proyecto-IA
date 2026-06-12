Datasets reales y públicos
==========================

Aqui se pueden colocar los corpus externos para que SentinelMail AI los use automáticamente
en el entrenamiento y en la validación.

Formatos soportados:

1. CSV
   Columnas aceptadas:
   - subject o asunto
   - body, text, message o contenido
   - url o link
   - label, class o type

   Valores de etiqueta aceptados:
   - Phishing: 1, true, phishing, malicious, spam, fraud
   - Legítimo: 0, false, legit, legitimate, ham, normal

2. JSON
   Puede ser una lista de objetos o un objeto con propiedad "rows".

3. JSONL
   Un objeto JSON por línea.

4. EML
   Para archivos .eml, coloque los correos dentro de carpetas cuyo nombre indique
   la clase:
   - phishing, malicious, spam o fraud
   - legit, legitimate, ham o normal

Ejemplos de corpus públicos que se pueden adaptar:
- Enron Email Dataset, para correos legítimos.
- Nazario Phishing Corpus, para correos phishing históricos.
- PhishTank u OpenPhish, para URLs sospechosas combinadas con texto de correo.

Nota: no se incluyen correos maliciosos reales dentro del repositorio para evitar
distribuir enlaces o adjuntos peligrosos. El cargador permite incorporarlos de
forma local y controlada durante la demostración o evaluación académica.
