FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY app.py .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
