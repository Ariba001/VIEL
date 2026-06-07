FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# System deps: gcc for dataset generation, Java for Ghidra, Python 3.11
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3.11-dev \
    python3-pip \
    gcc \
    build-essential \
    openjdk-17-jre-headless \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Make python3.11 the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1

WORKDIR /app

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ghidra is large (~1 GB) — mount it as a volume rather than baking it in.
# Set the path via environment variable or .env file.
# docker run -e GHIDRA_HEADLESS=/ghidra/support/analyzeHeadless \
#            -v /path/to/ghidra:/ghidra ...
ENV GHIDRA_HEADLESS=/ghidra/support/analyzeHeadless

CMD ["bash"]
