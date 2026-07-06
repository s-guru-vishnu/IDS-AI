FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY . .

# Expose port
EXPOSE 5005

# Run the application (Render injects $PORT automatically)
CMD ["sh", "-c", "gunicorn server:app -b 0.0.0.0:${PORT:-5005}"]
