# Use an official Python runtime as base
FROM python:3.13-slim

# Set work directory inside container
WORKDIR /app
COPY src ./src/

# Copy only requirements first to leverage Docker cache
COPY requirements.txt .
# Copy rest of the application code
COPY flag.txt /flag.txt
RUN sh -c 'FLAG_NAME=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12) && mv /flag.txt /flag_${FLAG_NAME}.txt'

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR src

# Set default command
CMD ["python", "app.py"]
