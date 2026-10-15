FROM python:3.11-slim

# git is needed for history scans (GitPython shells out to it).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Scans unpack untrusted repositories; don't do it as root.
RUN useradd --create-home --uid 10001 cipherwatch && chown -R cipherwatch /app
USER cipherwatch

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
