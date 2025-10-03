# Use a slim and secure Python base image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the working directory
COPY . .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app will run on
EXPOSE 8080

# The command to run the Streamlit application
# Using --server.address=0.0.0.0 makes it accessible from outside the container
CMD ["streamlit", "run", "Pega_Log_Troubleshooter.py", "--server.port=8080", "--server.headless=true", "--server.address=0.0.0.0"]