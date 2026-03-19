FROM node:20-alpine AS frontend-builder

WORKDIR /app/recon_frontend

COPY recon_frontend/package*.json ./
RUN npm install

COPY recon_frontend/ ./
RUN npm run build

FROM golang:1.25 AS tools-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ARG SUBFINDER_VERSION=latest
ARG HTTPX_VERSION=latest
ARG NAABU_VERSION=latest
ARG AMASS_VERSION=main
ARG ASSETFINDER_VERSION=latest
ARG GAU_VERSION=latest
ARG WAYBACKURLS_VERSION=latest

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
    && CGO_ENABLED=0 go install -v github.com/owasp-amass/amass/v5/cmd/amass@${AMASS_VERSION} \
    && go install github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION} \
    && go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} \
    && go install github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION}

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
        nmap \
    && (apt-get install -y --no-install-recommends libpcap0.8 || apt-get install -y --no-install-recommends libpcap0.8t64) \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
COPY --from=frontend-builder /app/recon_frontend/dist /app/recon_frontend/dist
COPY --from=tools-builder /go/bin/ /usr/local/bin/

COPY backend/docker-entrypoint.sh /app/backend/docker-entrypoint.sh
RUN chmod +x /app/backend/docker-entrypoint.sh

RUN useradd --create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

ENTRYPOINT ["/app/backend/docker-entrypoint.sh"]
