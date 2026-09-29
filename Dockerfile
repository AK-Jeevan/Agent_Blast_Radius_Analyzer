# =============================================================================
# Agent Blast-Radius Analyzer
# Multi-stage: the API and the UI ship from the same image, selected by command.
# =============================================================================
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# --- dependency layer (cached unless requirements change) -------------------------
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- application layer ------------------------------------------------------------
COPY app ./app
COPY data ./data
COPY gradio_app ./gradio_app
COPY docs ./docs
COPY pyproject.toml README.md ./

# tests/ travels with the code on purpose: the container workflow verifies the *image* rather than
# the checkout, by running the architecture invariants inside it --
# ``docker run --rm analyzer:verify python -m pytest tests/unit/test_architecture.py -q``. Shipping
# the code without the tests that check it made that step fail on a missing path.
COPY tests ./tests

# Artifacts are written to a mounted volume; never bake results into the image.
RUN mkdir -p /app/artifacts && \
    useradd --create-home --uid 10001 analyzer && \
    chown -R analyzer:analyzer /app
USER analyzer

# Provenance labels go last on purpose. An ARG declared above a RUN invalidates that RUN whenever the
# value changes, so declaring VCS_REF at the top would re-run `pip install` on every rebuild with a
# new revision. Here, a new revision only rebuilds this final metadata layer.
#   docker build --build-arg VCS_REF=$(git rev-parse --short HEAD) --build-arg BUILD_DATE=$(date -u +%FT%TZ) .
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Agent Blast-Radius Analyzer" \
      org.opencontainers.image.description="Effective blast-radius analysis for AI agents: identities, tools, credentials, composition, and impact." \
      org.opencontainers.image.source="https://github.com/AK-Jeevan/Agent_Blast_Radius_Analyzer" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"

EXPOSE 8000 7860

# Default: the API. Override the command to run the UI instead.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
url='http://127.0.0.1:'+os.environ.get('API_PORT','8000')+'/health'; \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status==200 else 1)"
