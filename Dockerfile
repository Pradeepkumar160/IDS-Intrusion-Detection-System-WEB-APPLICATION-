FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Retrain model inside Docker so numpy versions always match
RUN python ml/train.py
EXPOSE 5000
CMD ["python", "run.py"]
