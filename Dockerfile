# Created by Sunny Chase (https://github.com/sunnychase) in collaboration with Claude (Anthropic) · Lion Studio - Container Port Dash
FROM python:3.12-slim
# busctl (systemd --user over D-Bus), ss and ip (iproute2); paramiko asks the machine's own SSH server to check the Kill password
RUN apt-get update && apt-get install -y --no-install-recommends systemd iproute2 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir paramiko==3.5.1
COPY app.py /app/app.py
RUN chmod 755 /app && chmod 644 /app/app.py
USER 1000:1000
ENV PORTS_BIND=0.0.0.0 PORTS_PORT=8660 PORTS_DATA=/data PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=ignore
CMD ["python3", "/app/app.py"]
