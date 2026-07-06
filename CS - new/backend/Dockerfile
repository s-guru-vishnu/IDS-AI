FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY backend/ ./backend/

# Expose port
EXPOSE 5005

# Run the application
CMD ["gunicorn", "--chdir", "backend", "server:app", "-b", "0.0.0.0:5005"]
