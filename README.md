# Alamaticz-IdentifAI

Log Troubleshooter utility for analyzing and identifying issues in Pega logs.

## Overview
A lightweight Python tool to assist in quickly scanning log files, highlighting errors, warnings, and potential root causes.

## Features
- Upload JSON / JSONL Pega logs and query them in natural language
- Automatic OpenSearch indexing + SQL-style querying (filtered per session)
- Follow-up question memory (context-aware queries)
- Inline error root cause diagnosis (LLM powered)
- Web search for fixes (Pega Community, docs, etc.)
- Feedback capture stored to S3 (if configured)
- Sensitive value masking before sending to AI models
- Containerized deployment (Docker) with CI image publishing

## Tech Stack / Key Libraries
| Purpose | Library |
|---------|---------|
| UI & App | streamlit |
| Log storage/search | opensearch-py |
| LLM Orchestration | crewai / crewai-tools |
| OpenAI API wrapper | langchain-openai (via LangChain) |
| Conversation memory | langchain |
| Environment vars | python-dotenv |
| Data handling | pandas |
| HTTP | requests |
| AWS feedback storage | boto3 |

See `requirements.txt` for the complete list.

## Prerequisites
- Python 3.10+ (recommended) OR Docker
- An OpenSearch endpoint (set OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS, INDEX_NAME)
- OpenAI (or compatible) API key for LLM usage: set `OPENAI_API_KEY`
- (Optional) AWS credentials + `FEEDBACK_S3_BUCKET` for feedback storage

## Environment Variables (.env example)
```
OPENSEARCH_URL=https://your-opensearch-endpoint:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=changeme
INDEX_NAME=pega-logs
OPENAI_API_KEY=sk-...
FEEDBACK_S3_BUCKET=your-feedback-bucket
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

## Local Setup (Windows PowerShell)
```powershell
# 1. Clone / open project directory
cd "c:\Users\<you>\Desktop\Projects\Log Troubleshooter"

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip (optional but recommended)
python -m pip install --upgrade pip

# 4. Install dependencies
pip install -r requirements.txt

# 5. Create a .env file (if not present) and populate required variables
notepad .env

# 6. Run the Streamlit app
streamlit run Pega_Log_Troubleshooter.py
```

## Run with Docker
Build & run locally (without compose):
```powershell
docker build -t log-troubleshooter:local .
# Pass env vars directly or mount an env file
$env:OPENAI_API_KEY="sk-..."; docker run --rm -p 8501:8501 `
  -e OPENAI_API_KEY=$env:OPENAI_API_KEY `
  -e OPENSEARCH_URL=http://host.docker.internal:9200 `
  -e OPENSEARCH_USER=admin -e OPENSEARCH_PASS=admin `
  -e INDEX_NAME=pega-logs log-troubleshooter:local
```
Navigate to http://localhost:8501.

## Run Full Stack with docker-compose
A local OpenSearch + App stack is provided.
```powershell
# (Optional) adjust values in .env.docker
notepad .env.docker

# Start services
docker compose up --build

# Tear down
docker compose down -v
```
App: http://localhost:8501  |  OpenSearch API: http://localhost:9200

## GitHub Container Registry (GHCR) Image
A GitHub Actions workflow (`.github/workflows/docker-build.yml`) builds and pushes multi-arch images on pushes & PRs to `main`.

Image naming convention:
```
ghcr.io/<owner>/log-troubleshooter:latest
ghcr.io/<owner>/log-troubleshooter:<git-sha7>
```
(Optional) Add a `VERSION` file at repo root to set a semantic version tag (e.g., `1.0.0`).

### Pull & Run Published Image
```powershell
docker pull ghcr.io/<owner>/log-troubleshooter:latest
docker run -p 8501:8501 `
  -e OPENAI_API_KEY=sk-... `
  -e OPENSEARCH_URL=https://your-opensearch:9200 `
  -e OPENSEARCH_USER=admin -e OPENSEARCH_PASS=changeme `
  -e INDEX_NAME=pega-logs ghcr.io/<owner>/log-troubleshooter:latest
```

## CI/CD Workflow Summary
- Triggers: push, pull_request on `main`, manual dispatch.
- Builds multi-arch (amd64 + arm64) image.
- Tags with `latest` (or `VERSION` file value) and short SHA.
- Publishes to GHCR using `GITHUB_TOKEN` (no extra secrets needed).

## Troubleshooting
| Issue | Cause | Fix |
|-------|-------|-----|
| ModuleNotFoundError: opensearchpy | Dependency not installed | `pip install -r requirements.txt` |
| OpenSearch auth failure | Wrong credentials / URL | Verify env vars & network access |
| Empty query results | Index not created or no matching logs | Upload logs first; check `INDEX_NAME` |
| LLM errors | Missing `OPENAI_API_KEY` or quota | Set key / verify usage |
| Feedback not saved | S3 bucket or IAM misconfigured | Check bucket name, region, IAM policy |
| Docker healthcheck failing | App not starting or port blocked | Check logs: `docker logs <container>` |
| Compose app waits forever | OpenSearch not healthy yet | Ensure sufficient memory (≥2GB) for OpenSearch |

## Usage Flow
1. Launch app.
2. Upload log file (JSON objects per line recommended).
3. Ask queries like:
	- "show 10 error logs"
	- "count errors"
	- "group by app"
	- Follow-up: "how many debug in previous result"
4. Click 🔧 Diagnose for targeted root cause analysis.
5. Click 🌐 Search Web to pull possible documented solutions.
6. Provide feedback via 👍 / 👎 to store structured review in S3.

## Security & Privacy Notes
- Basic masking applied to emails, URLs, IPs, hostnames, and IDs before LLM calls.
- Review masking patterns in `mask_sensitive_data` for your environment; extend as needed.
- Do NOT commit real credentials—use `.env` locally, `.env.docker` for compose (avoid pushing secrets), and GH secrets for production.

## Roadmap Ideas
- Add unit tests for masking and SQL rewrite logic
- Version pin dependencies for reproducibility
- Add pagination & sorting in log table
- Support multi-session search history
- Add retry/backoff for OpenSearch failures
- Add automated security scanning (Dependabot, Trivy)

## License
Currently internal / unspecified. Add appropriate license before distribution.

---
Enhanced documentation including dependency, containerization & CI instructions.
