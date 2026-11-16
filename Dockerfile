# WD CYBER TOOLKIT NEO — container image.
#
# Build:  docker build -t wd-cyber-toolkit-neo .
# Run:    docker run --rm -p 8000:8000 -v wd_data:/app/database -v wd_ev:/app/evidence wd-cyber-toolkit-neo
#
# The image includes the external CLI tools the engines drive (nmap, tshark,
# tcpdump, can-utils, arping, yara, dig, whois) so "live" checks actually run.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    WD_HOST=0.0.0.0 \
    WD_PORT=8000

# tshark asks interactively whether non-root may capture; preseed the answer.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap tshark tcpdump iputils-arping can-utils dnsutils whois \
      curl openssl yara jq ca-certificates libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Capture binaries need raw-socket capability when the app runs as non-root.
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap 2>/dev/null || true

RUN mkdir -p database evidence reports \
 && useradd -m -u 10001 wdneo \
 && chown -R wdneo:wdneo /app

USER wdneo
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
