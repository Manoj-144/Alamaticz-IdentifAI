# Use a slim and secure Python base image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies (needed for pysqlite3-binary, crewai, etc.)
RUN apt-get update && apt-get install -y \
    gcc \
    libsqlite3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy all project files into the working directory
COPY . .

# Install the Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Expose the port the app will run on
EXPOSE 8080

# The command to run the Streamlit application
CMD ["streamlit", "run", "Pega_Log_Troubleshooter.py", "--server.port=8080", "--server.headless=true", "--server.address=0.0.0.0"]
