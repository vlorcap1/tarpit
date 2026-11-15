FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./

# En contenedor escucha en todas las interfaces; nginx le pasa el tráfico.
ENV TARPIT_HOST=0.0.0.0 \
    TARPIT_PORT=8080 \
    TARPIT_WEIGHTS=/data/weights.json

EXPOSE 8080
CMD ["python", "app.py"]
