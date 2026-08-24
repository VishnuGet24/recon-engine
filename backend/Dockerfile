FROM node:20-alpine AS frontend-builder

WORKDIR /app/recon_frontend

COPY recon_frontend/package*.json ./
RUN npm install

COPY recon_frontend/ ./
RUN npm run build

FROM golang:1.24-bookworm AS tools-builder

ENV GOTOOLCHAIN=auto

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ARG SUBFINDER_VERSION=latest
ARG NAABU_VERSION=latest
ARG ASSETFINDER_VERSION=latest
ARG GAU_VERSION=latest
ARG WAYBACKURLS_VERSION=latest

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
    && go install -v github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION} \
    && go install -v github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} \
    && go install -v github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION}

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app/backend

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        wget \
        dnsutils \
        net-tools \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
COPY --from=frontend-builder /app/recon_frontend/dist /app/recon_frontend/dist
COPY --from=tools-builder /go/bin/ /usr/local/bin/

COPY backend/docker-entrypoint.sh /app/backend/docker-entrypoint.sh
RUN sed -i 's/\r$//' /app/backend/docker-entrypoint.sh \
    && chmod +x /app/backend/docker-entrypoint.sh

RUN useradd --create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

ENTRYPOINT ["/app/backend/docker-entrypoint.sh"]
