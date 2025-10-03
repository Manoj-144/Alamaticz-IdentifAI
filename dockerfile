FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libsqlite3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["streamlit", "run", "Pega_Log_Troubleshooter.py", "--server.port=8080", "--server.headless=true", "--server.address=0.0.0.0"]
