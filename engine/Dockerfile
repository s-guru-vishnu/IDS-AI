FROM python:3.12-slim

WORKDIR /app/engine

# Install system dependencies for scapy packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy engine source code and models
COPY . .

# Create logs directory
RUN mkdir -p logs

# Run the engine (requires NET_RAW capability for packet capture)
# Use: docker run --cap-add=NET_RAW --net=host ids-engine
CMD ["python", "-u", "main.py"]
