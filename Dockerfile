# No dependencies to install: the server is the Python standard library only.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY mailbox.py server.py ./

# Run as a non-root user; nothing here needs to write to disk.
RUN useradd --create-home --shell /usr/sbin/nologin bridge
USER bridge

EXPOSE 8080

CMD ["python", "server.py"]
