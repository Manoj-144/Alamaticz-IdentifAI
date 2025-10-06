# Alamaticz-IdentifAI

Log Troubleshooter utility for analyzing and identifying issues in Pega logs.

## Overview
A lightweight Python tool to assist in quickly scanning log files, highlighting errors, warnings, and potential root causes.

## Features
- Upload JSON / JSONL Pega logs and query them in natural language
- Automatic OpenSearch indexing + SQL-style querying (filtered per session)
- Structured intent orchestration (LLM-based) for routing & follow-up detection
- Follow-up question memory (CrewAI + LangChain windowed context)
- Inline error root cause diagnosis (LLM powered)
- Web search for fixes (Pega Community, docs, etc.)
- Feedback capture stored to S3 (if configured)
- Sensitive value masking before sending to AI models

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
- Python 3.10+ (recommended)
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

## Troubleshooting
| Issue | Cause | Fix |
|-------|-------|-----|
| ModuleNotFoundError: opensearchpy | Dependency not installed | `pip install -r requirements.txt` |
| OpenSearch auth failure | Wrong credentials / URL | Verify env vars & network access |
| Empty query results | Index not created or no matching logs | Upload logs first; check `INDEX_NAME` |
| LLM errors | Missing `OPENAI_API_KEY` or quota | Set key / verify usage |
| Feedback not saved | S3 bucket or IAM misconfigured | Check bucket name, region, IAM policy |

## Usage Flow
1. Launch app.
2. Upload log file (JSON objects per line recommended).
3. Ask queries like:
	- "show 10 error logs"
	- "count errors"
	- "group by app"
	- Follow-up: "how many debug in previous result"
4. Internally, your message is first analyzed by an Orchestrator agent which returns a compact, machine-parsable block:
```
INTENT: log_query
FOLLOW_UP: true
CONTEXT: Previous query returned 42 logs with 10 ERROR, 5 WARN
QUERY: how many debug logs
```
5. If FOLLOW_UP is true, the CONTEXT plus QUERY are merged and sent to the SQL Query Builder agent; otherwise the QUERY alone is used.
6. A concise summary of the latest dataset (count + level distribution) is stored as `last_query_context` for the next turn.
7. Click 🔧 Diagnose for targeted root cause analysis.
8. Click 🌐 Search Web to pull possible documented solutions.
9. Provide feedback via 👍 / 👎 to store structured review in S3.
4. Click 🔧 Diagnose for targeted root cause analysis.
5. Click 🌐 Search Web to pull possible documented solutions.
6. Provide feedback via 👍 / 👎 to store structured review in S3.

## Security & Privacy Notes
- Basic masking applied to emails, URLs, IPs, hostnames, and IDs before LLM calls.
- Review masking patterns in `mask_sensitive_data` for your environment; extend as needed.
- Do NOT commit real credentials—use `.env` locally and keep secrets out of version control.

## Roadmap Ideas
- Add unit tests for masking and SQL rewrite logic
- Persist orchestrator memory across browser refresh (optional encrypted store)
- Version pin dependencies for reproducibility
- Add pagination & sorting in log table
- Support multi-session search history
- Add retry/backoff for OpenSearch failures
- Add automated security scanning (Dependabot, Trivy)

## License
Currently internal / unspecified. Add appropriate license before distribution.

---
Documentation updated after removing containerization assets.
