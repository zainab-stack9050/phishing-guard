FROM python:3.12-slim

# Run as a normal user, not root
RUN useradd --create-home --uid 1000 crawler

WORKDIR /app
RUN pip install --no-cache-dir "requests>=2.32.4"
COPY fetch_phish.py .

USER crawler
ENV DATA_DIR=/data
ENTRYPOINT ["python", "fetch_phish.py"]
