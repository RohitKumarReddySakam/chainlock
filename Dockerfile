FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 chainlock && chown -R chainlock:chainlock /app
USER chainlock
EXPOSE 5001
ENV PYTHONUNBUFFERED=1
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--timeout", "120", "wsgi:app"]
