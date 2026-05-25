FROM python:3.12-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git jq yara libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install gitleaks
RUN arch=$(uname -m) && \
    gitleaks_arch="x64" && \
    [ "$arch" = "aarch64" ] && gitleaks_arch="arm64" && \
    latest=$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name') && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${latest}/gitleaks_${latest:1}_linux_${gitleaks_arch}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# Create app user and dirs
RUN useradd -m -s /bin/bash frisk
ENV FRISK_HOME=/home/frisk/.frisk
ENV FRISK_INTEL_DIR=/home/frisk/.frisk/intel
WORKDIR /home/frisk/app

# Copy package files first for layer caching
COPY package.json package-lock.json* ./
RUN npm install --production

# Copy Python requirements
COPY requirements.txt ./
RUN python3 -m venv ${FRISK_HOME}/venv && \
    ${FRISK_HOME}/venv/bin/pip install --quiet --upgrade pip && \
    ${FRISK_HOME}/venv/bin/pip install --quiet -r requirements.txt

# Copy application code
COPY . .

# Create data dirs
RUN mkdir -p ${FRISK_INTEL_DIR}/{cisa-kev,osv,epss,malwarebazaar,urlhaus,threatfox,feodo,yara-rules,semgrep-rules} \
    ${FRISK_HOME}/reports

# Expose API port
EXPOSE 3100

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsSL http://localhost:3100/health || exit 1

# Run API server
USER frisk
CMD ["node", "api/src/server.js"]