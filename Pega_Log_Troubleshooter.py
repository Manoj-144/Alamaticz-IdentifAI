# Fix for SQLite compatibility on Streamlit Cloud
import sys
try:
    __import__('pysqlite3')
    sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
except ImportError:
    pass

import json, html, re, os
import requests
from opensearchpy import exceptions
import streamlit as st
import uuid
from dotenv import load_dotenv
from opensearchpy import OpenSearch, helpers
from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool
from crewai.tools import BaseTool
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferWindowMemory
import ast, warnings, asyncio
import pandas as pd
import datetime, time
from io import StringIO
import boto3

# Load environment variables
load_dotenv()

# --- Configuration ---
Query_llm = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0.1,
    streaming=True,
)

Solution_llm = ChatOpenAI(
    model="gpt-5",
    temperature=1,
    streaming=True,
)

# Orchestrator LLM 
Orchestrator_llm = ChatOpenAI(
    model="gpt-4-turbo",
    temperature=0.3,
    streaming=False,
)


OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = os.environ.get("INDEX_NAME")

# --- Silence warnings ---
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)
requests.packages.urllib3.disable_warnings()

# --- Fix asyncio "no current event loop" issue for Streamlit ---
try:
    asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# --- OpenSearch Client ---
client = OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True
    )

# --- Streamlit Configuration ---
st.set_page_config(
    page_title="AI Log Troubleshooter",
    page_icon="alamaticz_logo.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Global Styles ---
css_path = os.path.join(os.path.dirname(__file__), "styles.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
else:
    st.warning("styles.css not found – default styling only.")

# --- Inline Spinner Styles (idempotent) ---
st.markdown(
    """
<style>
.lt-thinking-box {display:flex;align-items:center;gap:10px;padding:6px 12px;border:1px solid #2d6cdf33;background:#2d6cdf10;border-radius:8px;font-size:0.85rem;color:#2d6cdf;margin:4px 0 8px 0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
.lt-spinner {width:20px;height:20px;border:3px solid #b9d4ff;border-top:3px solid #2d6cdf;border-radius:50%;animation:lt-spin 0.85s linear infinite;}
@keyframes lt-spin {0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}
</style>
""",
    unsafe_allow_html=True
)

# --- Initialize Session State ---
if "session_id" not in st.session_state:
    st.session_state.session_id = None 
if "messages" not in st.session_state:
    st.session_state.messages = []
if "diagnosis_cache" not in st.session_state:
    st.session_state.diagnosis_cache = {}
if "feedback_open_for" not in st.session_state:
    st.session_state.feedback_open_for = {}  
if "feedback_text" not in st.session_state:
    st.session_state.feedback_text = {}
if "last_query_time" not in st.session_state:
    st.session_state.last_query_time = 0
if "last_dataframe" not in st.session_state:
    st.session_state.last_dataframe = None
if "conversation_topics" not in st.session_state:
    st.session_state.conversation_topics = []
if "last_query_context" not in st.session_state:
    st.session_state.last_query_context = ""

# LangChain memory for follow-up context (window of 4 turns)
if "lc_memory" not in st.session_state:
    st.session_state.lc_memory = ConversationBufferWindowMemory(k=4, return_messages=True)


# --- Data Masking Function ---
def mask_sensitive_data(data: dict) -> dict:
    """
    Mask sensitive information such as email addresses, URLs, ticket numbers, IP addresses,
    internal identifiers like hostnames, pod names, cluster names, etc., in the error data dict.
    Returns a new dict with masked values.
    """
    def mask_value(val):
        if not isinstance(val, str):
            return val
        
        # email addresses
        val = re.sub(r"[\w\.-]+@[\w\.-]+", "[EMAIL]", val)
        
        # URLs (http/https, domain, path)
        val = re.sub(r"https?://[\w\.-]+(?:/[\w\.-]*)*", "[URL]", val)
        
        # ticket numbers (e.g., TKT-12345, INC123456, SR12345678)
        val = re.sub(r"\b([A-Z]{2,5}-?\d{4,10})\b", "[TICKET]", val)
        
        # IP addresses (IPv4)
        val = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", val)
        
        # 16+ digit numbers (possible credit cards, etc.)
        val = re.sub(r"\b\d{16,}\b", "[LONG_NUMBER]", val)
        
        # phone numbers (simple patterns)
        val = re.sub(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE]", val)
        
        # hostnames, pod names, and source nodes (patterns like 'pega-web-77d5f7bb-vrkcb')
        val = re.sub(r"\bpega-[\w-]+\b", "[HOST]", val)
        
        # cluster names (like 'cluster-u6gzd4kxv70edgrbvam8zx14')
        val = re.sub(r"\bcluster-[\w\d]+\b", "[CLUSTER]", val)
        
        # namespace names (like 'pdsllc-pdsonb-prod1')
        val = re.sub(r"\b[a-z0-9\-]+-prod\d\b", "[NAMESPACE]", val)
        
        # rule sets (like 'pyRuleSet=' or patterns resembling rule names)
        val = re.sub(r"\bpyRuleSet=[\w\-]*", "pyRuleSet=[RULESET]", val)
        
        # identifiers like 'pzInsKey' followed by data
        val = re.sub(r"\bpzInsKey=[\w\-]*", "pzInsKey=[MASKED]", val)
        
        # file paths like '/datacontent/image/gen_...js'
        val = re.sub(r"/[\w\-/\.]*", "[FILE_PATH]", val)
        
        return val

    def mask_dict(d):
        masked = {}
        for k, v in d.items():
            if isinstance(v, dict):
                masked[k] = mask_dict(v)
            elif isinstance(v, list):
                masked[k] = [mask_dict(i) if isinstance(i, dict) else mask_value(i) for i in v]
            else:
                masked[k] = mask_value(v)
        return masked

    return mask_dict(data)


def ensure_index():
    """Ensure the index exists with proper mapping"""
    if client is None:
        # OpenSearch not configured
        return False
    mapping = {
        "mappings": {
            "properties": {
                "date": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                "time": {"type": "text"},
                "clusterName": {"type": "keyword"},
                "region": {"type": "keyword"},
                "environmentType": {"type": "keyword"},
                "pod_name": {"type": "keyword"},
                "container_name": {"type": "keyword"},
                "namespace_name": {"type": "keyword"},
                "host": {"type": "keyword"},
                "stream": {"type": "keyword"},
                "log": {
                    "properties": {
                        "level": {"type": "keyword"},
                        "message": {"type": "text"},
                        "stack": {"type": "text"},
                        "logger_name": {"type": "keyword"},
                        "source_host": {"type": "keyword"},
                        "timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                        "pegathread": {"type": "keyword"},
                        "thread_name": {"type": "keyword"},
                        "app": {"type": "keyword"},
                        "nodeId": {"type": "keyword"},
                        "nodeType": {"type": "keyword"},
                        "RequestorId": {"type": "keyword"},
                        "CorrelationId": {"type": "keyword"},
                        "userid": {"type": "keyword"},
                        "appender_ref": {"type": "keyword"},
                        "version": {"type": "integer"},
                        "exception": {
                            "properties": {
                                "exception_class": {"type": "keyword"},
                                "exception_message": {"type": "text"}
                            }
                        }
                    }
                },
                "session_id": {"type": "keyword"}
            }
        }
    }
    
    try:
        if not client.indices.exists(index=INDEX_NAME):
            client.indices.create(index=INDEX_NAME, body=mapping)
            return True
        else:
            return True
    except Exception as e:
        return False

# Initialize index on import
ensure_index()

# --- Upload Logs ---
def upload_logs_from_chat(uploaded_file):
    """Upload logs and return status message for chat"""
    if uploaded_file is None:
        return "❌ Please upload a log file first."
        
    if not ensure_index():
        return "❌ OpenSearch is not configured or the index could not be verified. Please set OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS, and INDEX_NAME."

    start_time = time.time()
    session_id = str(uuid.uuid4())
    actions = []
    total_lines = 0
    
    try:
        content = uploaded_file.read().decode('utf-8')
        lines = content.strip().split('\n')
        total_lines = len([line for line in lines if line.strip()])
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                log_entry = json.loads(line)
                log_entry['session_id'] = session_id
                actions.append({"_index": INDEX_NAME, "_source": log_entry})
            except json.JSONDecodeError:
                continue

        if actions:
            bulk_response = helpers.bulk(client, actions, refresh=True)
            successful_count = len(actions) - len(bulk_response[1]) if bulk_response[1] else len(actions)
            
            client.indices.refresh(index=INDEX_NAME)
            
            st.session_state.session_id = session_id
            st.session_state.total_logs = total_lines
            st.session_state.indexed_logs = successful_count
            st.session_state.diagnosis_cache = {}
            
            try:
                total_count = client.count(index=INDEX_NAME)['count']
            except:
                total_count = "unknown"
            
            processing_time = time.time() - start_time
            
            return f"""✅ **Upload Successful!**

                📊 Upload Summary:

                • File processed: {uploaded_file.name}

                • Total log entries in file: {total_lines:,}

                • Successfully indexed: {successful_count:,}

                • Session ID: {session_id}

                ⏱️ Processing time: {processing_time:.2f} seconds

                🗄️ Database Status:
                
                Total logs in database: {total_count:,}

                You can now ask me questions about your logs!"""
        else:
            return "❌ No valid JSON log entries found in the file."
            
    except Exception as e:
        return f"❌ Error during upload: {str(e)}"

# --- Fast OpenSearch SQL Tool ---
class FastOpenSearchSqlTool(BaseTool):
    name: str = "Fast OpenSearch SQL Tool"
    description: str = "Executes OpenSearch SQL queries and returns results immediately without post-processing."
    result_as_answer: bool = True 
    session_id: str | None = None

    def _run(self, query: str):
        if not self.session_id:
            return {"error": "Session ID is not set."}

        if client is None:
            return {"error": "OpenSearch is not configured. Please set OPENSEARCH_URL and credentials."}
        if not client.indices.exists(index=INDEX_NAME):
            return {"error": f"Index '{INDEX_NAME}' does not exist. Please upload logs first."}

        sql_query = query.strip()
        if not sql_query:
            return {"error": "An empty query was provided."}

        where_clause = f"WHERE session_id = '{self.session_id}'"
        
        if 'where' in sql_query.lower():
            final_query = re.sub(r'\s+where\s+', f' {where_clause} AND ', sql_query, flags=re.IGNORECASE, count=1)
        else:
            clauses_to_check = ['LIMIT', 'GROUP BY', 'ORDER BY']
            insert_pos = -1

            for clause in clauses_to_check:
                pos = sql_query.upper().find(clause)
                if pos != -1:
                    if insert_pos == -1 or pos < insert_pos:
                        insert_pos = pos
            
            if insert_pos != -1:
                part1 = sql_query[:insert_pos].strip()
                part2 = sql_query[insert_pos:].strip()
                final_query = f"{part1} {where_clause} {part2}"
            else:
                final_query = f"{sql_query} {where_clause}"

        print(f"[DEBUG] Executing SQL: {final_query}")
        try:
            response = client.transport.perform_request(
                'POST',
                '/_plugins/_sql',
                body={'query': final_query}
            )
            
            if 'schema' in response and 'datarows' in response:
                columns = [col['name'] for col in response['schema']]
                results = [dict(zip(columns, row)) for row in response['datarows']]
                return results
            else:
                return {"error": "Query executed, but response format was unexpected.", "data": response}
        except exceptions.RequestError as e:
            error_details = "No additional details provided."
            if e.info and isinstance(e.info, dict) and 'error' in e.info and isinstance(e.info['error'], dict):
                error_details = e.info['error'].get('reason', str(e))
            elif str(e):
                error_details = str(e)
            return {"error": f"SQL execution failed (400 - Bad Request). Check query syntax. Details: {error_details}"}
        
        except Exception as e:
            return {"error": f"An unexpected error occurred during SQL execution: {str(e)}"}
            
sql_tool = FastOpenSearchSqlTool()

# --- Agents ---
sql_query_builder_agent = Agent(
     role="SQL Query Builder",
     goal="Create optimized OpenSearch SQL queries and return tool results immediately, handling follow-up context when provided",
     backstory=(
          "You are an expert SQL query writer for OpenSearch. Your primary goal is to translate user questions into valid SQL queries for the `pega-logs` table. "
          "You MUST determine the correct query pattern based on the user's intent and the field data types."
          
          "--- CONTEXT HANDLING ---"
          "If the user query starts with 'Context from previous conversation:', you are handling a FOLLOW-UP question."
          "Parse the context to understand what the user is referring to:"
          "- If context mentions 'Previous query returned N logs', user is asking about those specific logs"
          "- If context mentions 'X DEBUG logs', user wants to count/filter those specific log levels"
          "- If context mentions specific apps/errors, focus the query on those"
          
          "FOLLOW-UP EXAMPLES:"
          "Context: 'Previous query returned 4 logs with 2 DEBUG entries' + Query: 'how many debug' → Count only DEBUG logs from those 4"
          "Context: 'User asked for logs from Deal app' + Query: 'show errors' → Show ERROR logs specifically from Deal app"
          "Context: 'Last query showed 20 logs' + Query: 'group by level' → GROUP BY log.level from the previous result set"
          
          "For follow-ups, MODIFY the base query to be more specific based on context."

          "--- FIELD CHEATSHEET ---"
          "1. `log.timestamp` (type: timestamp) -> Used for time-based filtering."
          "2. `log.level` (type: keyword) -> Used for filtering by level (e.g., 'ERROR', 'WARN'). Good for GROUP BY."
          "3. `log.app` (type: keyword) -> Used for filtering by application name. Good for GROUP BY."
          "4. `log.message` (type: text) -> Used for searching for text within a message using LIKE. CANNOT be used for COUNT, DISTINCT, or GROUP BY."
          "5. `log.stack` (type: text) -> Contains stack traces. CANNOT be used for COUNT, DISTINCT, or GROUP BY."
          "6. `log.exception.exception_class` (type: keyword) -> The specific exception class. Excellent for GROUP BY to find unique errors."

          "--- PEGA LOG QUERY EDGE CASES ---"
          "When building queries, handle these edge cases:"
          "- Ambiguous time ranges (e.g., 'today', 'last hour', 'yesterday', 'between 2 and 4pm')"
          "- Partial or fuzzy log levels (e.g., 'errors', 'warnings', 'critical issues', 'all logs')"
          "- Multiple filters in one query (e.g., 'errors for app X between 2pm and 3pm with message containing JWT')"
          "- Free-text search in messages (e.g., 'logs mentioning timeout')"
          "- Grouping/aggregation (e.g., 'count of errors by app', 'top 5 error types')"
          "- Pagination/limits (e.g., 'show last 10 errors', 'show next page')"
          "- Misspelled or missing fields (suggest corrections)"
          "- Date/time format variability (e.g., '2025-09-09', '09/09/2025', 'Sep 9, 2025')"
          "- No results/empty queries (respond helpfully)"
          "- Compound conditions (e.g., 'errors OR warnings', 'app is X AND level is ERROR')"
          "- Case sensitivity in field values"
          "- Special characters in search (e.g., emails, URLs, JSON)"
          "- Missing fields in some logs (handle gracefully)"
          "- Session/request/correlation ID filtering"
          "- Follow-up queries (e.g., 'show more like this', 'diagnose the last error')"
          "- Queries with case id, for example if the user asks to show logs containing case id ES-14404, the quesry should search for only 14404 because opensearch considers '-' as minus and not hyphen"

          "--- QUERY PATTERN PLAYBOOK ---"
          "1. TO FETCH DATA ('show', 'find', 'list'): Use SELECT with the priority column list. NEVER use `SELECT *`."
              "   - Priority Columns: `log.timestamp`, `log.app`, `log.level`, `log.message`, `log.exception.exception_class`, `log.exception.exception_message`, `log.stack`, `log.RequestorId`, `log.CorrelationId`."
              "   - Example: `SELECT `log.timestamp`, `log.app`, `log.level`, `log.message`, `log.stack`, `log.exception.exception_class`, `log.exception.exception_message` FROM `pega-logs` WHERE `log.level` = 'ERROR'`"
              " Always include stack column"

          "2. TO COUNT DATA ('how many', 'count', 'total', 'number of'): Use `COUNT(*)`. NEVER count a `text` field."
              "   - For error counts: `SELECT COUNT(*) FROM `pega-logs` WHERE `log.level` = 'ERROR'`"
              "   - For all logs: `SELECT COUNT(*) FROM `pega-logs``"
              "   - For specific app errors: `SELECT COUNT(*) FROM `pega-logs` WHERE `log.level` = 'ERROR' AND `log.app` = 'MyApp'`"

          "3. TO FIND UNIQUE ERRORS ('unique', 'distinct', 'group by'): Use `GROUP BY` on a `keyword` field like `log.exception.exception_class`. NEVER use the `DISTINCT` keyword on `text` fields."
              "   - Example: `SELECT `log.exception.exception_class`, COUNT(*) FROM `pega-logs` WHERE `log.level` = 'ERROR' GROUP BY `log.exception.exception_class``"

          "4. TO FILTER BY TIME/DATE ('between', 'at', 'on'): Use `BETWEEN` or other date functions on `log.timestamp`."
              "   - Example: `... WHERE `log.timestamp` BETWEEN '2025-08-28 14:00:00' AND '2025-08-28 15:00:00'`"

          "5. TO SEARCH TEXT ('logs that mention', 'containing'): Use the `LIKE` operator on `log.message` with wildcards (%)."
              "   - Example: `... WHERE `log.message` LIKE '%JWT%'`"
        
          "Always enclose full field paths in backticks. Log levels are UPPERCASE. Return the exact, raw tool output."
     ),
     verbose=False,
     tools=[sql_tool],
     llm=Query_llm,
     allow_delegation=False
)

# --- Orchestrator Agent ---
orchestrator_agent = Agent(
    role="Intent Classification & Delegation Layer",
    goal="Act as a pure NLP layer that identifies user intent and delegates to appropriate specialized agents without processing their outputs.",
    backstory=(
        "You are a smart intent classifier and task router for Pega log troubleshooting. Your ONLY job is to:"
        "1) Analyze user input to determine intent (log_query, diagnosis_request, upload_help, feedback, general_chat)"
        "2) Check if the user is asking a follow-up question that requires previous context"
        "3) Route the request to the appropriate specialized agent"
        "4) NEVER process or modify the outputs from other agents - pass them through directly"
        
        "INTENT CLASSIFICATION RULES:"
        "- log_query: User wants to search/filter/count logs (keywords: show, find, list, count, how many, errors, logs, between, from, app, level, message contains, group by, more details, debug, info, warn, etc.)"
        "- diagnosis_request: User wants root cause analysis of an error (keywords: diagnose, why, what caused, root cause, analyze error, troubleshoot)"
        "- upload_help: User asks about uploading logs or has upload issues"
        "- feedback: User provides feedback about responses"
        "- general_chat: Small talk, greetings, unrelated questions"
        
        "FOLLOW-UP DETECTION (CRITICAL):"
        "A query is a FOLLOW-UP if it refers to PREVIOUS RESULTS. Look for:"
        "- Direct references: 'previous result', 'the previous', 'those logs', 'that data', 'the results above', 'last query', 'from those'"
        "- Counting references: 'how many of those', 'count those', 'how many debug', 'how many in that'"
        "- Analysis of previous: 'group those by', 'filter those', 'show only the errors from that'"
        "- Modification: 'more details about those', 'show stack traces for those'"
        
        "NOT FOLLOW-UPS (standalone queries):"
        "- 'show 5 logs' (new query for 5 logs)"
        "- 'how many errors' (new query for all errors)"
        "- 'count debug logs' (new query for all debug logs)"
        
        "RESPONSE FORMAT (EXACT):"
        "INTENT: [intent_type]"
        "FOLLOW_UP: [true|false]"
        "CONTEXT: [relevant previous context if follow-up]"
        "QUERY: [exact query to pass to target agent]"
        
        "EXAMPLES:"
        "User: 'show 5 logs' → INTENT: log_query, FOLLOW_UP: false"
        "User: 'how many debug logs are in the previous result' → INTENT: log_query, FOLLOW_UP: true, CONTEXT: Previous query returned 4 logs with 2 DEBUG entries"
        "User: 'count those' → INTENT: log_query, FOLLOW_UP: true"
    ),
    verbose=False,
    tools=[],
    llm=Orchestrator_llm,
    allow_delegation=False
)

# LLM-only diagnosis agent (without SerperDevTool initially)
diagnosis_agent_llm = Agent(
    role="Pega Log Diagnosis LSA", 
    goal="Pinpoint the failing Pega rule from a log entry and provide a root cause analysis with actionable solutions.",
    backstory=(
        "You are a top-tier Pega Lead System Architect (LSA) specializing in debugging complex production issues. "
        "Your mission is to perform a root cause analysis on a given Pega JSON log entry and pinpoint the exact Pega rule, configuration, or integration point that is the source of the error. "
        "You must think like a Pega developer who is debugging a live system."

        "--- ANALYSIS PLAYBOOK ---"
        "1.  **Identify the Symptom:** Start with the `log.message`. This tells you *what* failed. In the example 'Error in Processing JWT', the symptom is a JSON Web Token processing failure."
        
        "2.  **Locate the Technical Component:** Examine the `log.logger_name`. This points to the underlying Java class that threw the error. For `com.pega...OAuth2DataProviderImpl`, this confirms the issue is within Pega's OAuth 2.0 provider services."

        "3.  **Pinpoint the Pega Rule Context (Crucial Step):** The `log.stack` field in these logs is NOT a Java stack trace. It is a Pega context stack, delimited by pipes (`|`). You MUST parse this field to find the specific rule that was running. "
        "   - The format is often: `nodeName|ipAddress|ServiceType|ServicePackage|ServiceVersion|ServiceRuleName|RequestorID`."
        "   - In the example `...|Rest|application|v2|data_views_var9221668ffe33b795bd9989d2c3c80c49|...`, the failing rule is the REST Service named `data_views_var9221668ffe33b795bd9989d2c3c80c49` in the `application` service package, version `v2`."

        "4.  **Synthesize and Conclude:** Combine these clues to form a precise conclusion. Your primary output MUST be identifying the failing rule from the `log.stack` field and explaining why it failed based on the other fields."
        
        "--- OUTPUT STRUCTURE ---"
        "Always structure your response as follows:"
        "1.  **Root Cause:** A brief, one-sentence summary of the problem."
        "2.  **Point of Failure (Pega Rule):** The full name of the Pega rule identified from the context stack."
        "3.  **Detailed Analysis:** Explain how you reached your conclusion by linking the `message`, `logger_name`, and the identified Pega rule."
        "4.  **Recommended Actions:** Provide clear, actionable steps for a Pega developer to investigate and fix the issue (e.g., 'Check the Authentication Profile associated with this Service REST rule', 'Verify the JWT configuration and keystore', 'Enable debugger on this service and trace the request')."
    ),
    verbose=False,
    tools=[],
    llm=Solution_llm,
    allow_delegation=False
)

# Web search diagnosis agent (with SerperDevTool)
diagnosis_agent_web = Agent(
    role="Pega Knowledge & Web Researcher", 
    goal="Find actual working links and relevant solutions for Pega errors by searching Pega Community and technical websites.",
    backstory=(
        "You are an expert web researcher who finds ACTUAL, WORKING links to Pega solutions. "
        "Your mission is to provide real, clickable URLs that users can visit for solutions."

        "--- SEARCH STRATEGY ---"
        "1. Search with targeted queries: 'site:community.pega.com [error_keywords]' for Pega Community"
        "2. Search 'site:docs.pega.com [error_keywords]' for official documentation"
        "3. Search 'site:stackoverflow.com pega [error_keywords]' for Stack Overflow"
        "4. Verify each URL is complete and properly formatted"

        "--- CRITICAL OUTPUT REQUIREMENTS ---"
        "1. ALWAYS provide COMPLETE, WORKING URLs (starting with https://)"
        "2. Test each URL format before including it"
        "3. For each solution, include: Problem description + Solution summary + WORKING URL"
        "4. If no working links found, clearly state 'No direct links found' and provide search suggestions"
        
        "--- OUTPUT FORMAT ---"
        "**Found Solutions:**"
        "• [Brief solution description]"
        "  **Link:** https://[complete-working-url]"
        "  **Summary:** [What this link contains]"
        
        "**Search Suggestions:**"
        "• Try searching: '[suggested search terms]'"
    ),
    verbose=False,
    tools=[SerperDevTool()],
    llm=Solution_llm,
    allow_delegation=False
)


# --- Feedback Functions ---
def save_feedback(feedback_type: str,
                  session_id: str,
                  message_id: str,
                  message_content: str,
                  user_comment: str,
                  full_conversation: list,
                  attached_dataframe_json: str | None = None) -> tuple[bool, str]:
    """
    Save feedback with rich context:
    - feedback_type: 'positive' | 'negative'
    - message_id/content: the assistant message being rated
    - user_comment: free text entered by the user
    - full_conversation: st.session_state.messages
    - attached_dataframe_json: if the message included a dataframe payload
    """
    try:
        feedback_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "feedback_type": feedback_type,
            "session_id": session_id,
            "message_id": message_id,
            "message_content": message_content,
            "user_comment": user_comment,
            "full_conversation": full_conversation,
            "attached_dataframe_json": attached_dataframe_json
        }

        # Build object key and JSON payload once
        object_key = f"feedback_{datetime.datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.json"
        payload = json.dumps(feedback_data, indent=2, ensure_ascii=False).encode("utf-8")

        # Resolve AWS configuration from env or Streamlit secrets
        bucket_name = os.environ.get("FEEDBACK_S3_BUCKET") 
        region = os.environ.get("AWS_REGION") 
        access_key = os.environ.get("AWS_ACCESS_KEY_ID") 
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY") 
        session_token = os.environ.get("AWS_SESSION_TOKEN") 

        if not bucket_name:
            return False, "FEEDBACK_S3_BUCKET not configured"

        # Create S3 client with available credentials/region
        if access_key and secret_key:
            s3 = boto3.client(
                "s3",
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
            )
        else:
            # Fall back to default credential chain (env, IAM role, etc.)
            s3 = boto3.client("s3", region_name=region)

        s3.put_object(Bucket=bucket_name, Key=object_key, Body=payload, ContentType="application/json; charset=utf-8")
        return True, object_key

    except Exception as e:
        # Return error for UI to surface
        return False, str(e)



# --- Create Results Display Functions ---

def flatten_dict(d, parent_key="", sep="."):
    """Recursively flattens nested dictionaries into dot-notation keys."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def create_results_dataframe(results_data):
    """Create pandas dataframe from query results with all available columns, expanding nested message JSON recursively."""
    if not results_data or not isinstance(results_data, list):
        return pd.DataFrame()
    
    flattened_results = []
    for item in results_data:
        flat_item = {}
        for key, value in item.items():
            clean_key = key.replace('log.exception.', '').replace('log.', '')

            # Special handling for 'message' if it contains a JSON string
            if clean_key == "message" and isinstance(value, str) and value.strip().startswith('{'):
                try:
                    match = re.search(r'\{.*\}', value, re.DOTALL)
                    if match:
                        json_str = match.group(0)
                        msg_json = json.loads(json_str)
                        msg_flat = flatten_dict(msg_json, parent_key="message")
                        flat_item.update(msg_flat)
                        flat_item["message_raw"] = value
                        continue
                except (json.JSONDecodeError, TypeError):
                    pass 

            flat_item[clean_key] = value if value is not None else ""
        flattened_results.append(flat_item)

    df = pd.DataFrame(flattened_results)

    # Priority columns
    priority_columns = [
        'timestamp', 'app', 'level', 'message', 'message.event.caseId', 'message_raw', 'stack','exception_class', 'exception_message',
        'RequestorId', 'CorrelationId'
    ]

    # Ensure RequestorId & CorrelationId always exist
    for _col in ['RequestorId', 'CorrelationId']:
        if _col not in df.columns:
            df[_col] = ""

    ordered_cols = [c for c in priority_columns if c in df.columns] + \
                     [c for c in df.columns if c not in priority_columns]
    df = df[ordered_cols]

    # Add Actions column if ERROR logs exist
    if 'level' in df.columns and any(df['level'].astype(str).str.contains('ERROR', na=False)):
        df['Actions'] = ""

    return df

def orchestrator_handle_user_input(user_input: str):
    """Pure intent classification and delegation layer that routes to appropriate agents."""
    
    # Simple follow-up detection based on keywords
    followup_keywords = [
        "previous result", "previous", "those", "that data", "above result", 
        "from that", "in those", "of the", "how many of", "count those", 
        "in the previous", "from the previous", "those logs", "that result"
    ]
    
    is_followup = any(keyword.lower() in user_input.lower() for keyword in followup_keywords)
    
    # Get last query context if it's a follow-up
    context = ""
    if is_followup:
        context = getattr(st.session_state, 'last_query_context', '')
        print(f"[DEBUG] FOLLOW-UP DETECTED! Context: {context}")
        
    # Determine intent - keep it simple
    user_lower = user_input.lower()
    if any(word in user_lower for word in ['show', 'find', 'list', 'count', 'how many', 'debug', 'error', 'logs', 'group by']):
        intent = "log_query"
    elif any(word in user_lower for word in ['diagnose', 'why', 'root cause', 'analyze']):
        intent = "diagnosis_request"
    elif any(word in user_lower for word in ['upload', 'file']):
        intent = "upload_help"
    elif any(word in user_lower for word in ['thank', 'feedback', 'good', 'bad']):
        intent = "feedback"
    else:
        intent = "general_chat"
    
    print(f"[DEBUG] Intent: {intent}, Follow-up: {is_followup}")
    
    # Handle log queries
    if intent == "log_query":
        # Build the query with context if it's a follow-up
        if is_followup and context:
            # For follow-ups, modify the user input to include context
            if "how many debug" in user_lower and "previous" in user_lower:
                # User wants to count DEBUG logs from previous result
                query = f"Context: {context}. Count only DEBUG logs from the previous result"
            elif "debug logs" in user_lower and ("previous" in user_lower or "above" in user_lower):
                # User wants only DEBUG logs from previous result
                query = f"Context: {context}. Show only DEBUG logs from the previous result"
            elif "only" in user_lower and "debug" in user_lower:
                # Show only debug from previous
                query = f"Context: {context}. Filter to show only DEBUG level logs from the previous result"
            else:
                query = f"Context: {context}. User query: {user_input}"
        else:
            query = user_input
            
        print(f"[DEBUG] Final query: {query}")
        
        result = execute_log_query(query)
        if isinstance(result, pd.DataFrame):
            # Store context about this query for follow-ups
            level_counts = result['level'].value_counts().to_dict() if 'level' in result.columns else {}
            app_info = result['app'].unique().tolist() if 'app' in result.columns else []
            
            query_context = f"Previous query returned {len(result)} logs"
            if level_counts:
                level_summary = ", ".join([f"{count} {level}" for level, count in level_counts.items()])
                query_context += f" with levels: {level_summary}"
            if app_info and len(app_info) <= 3:
                query_context += f" from apps: {', '.join(app_info)}"
            
            st.session_state.last_query_context = query_context
            print(f"[DEBUG] Stored context: {query_context}")
            
            # Store the dataframe and return summary
            df_json = result.to_json(orient='records')
            processing_time = getattr(st.session_state, 'last_query_time', 0)
            content = f"📊 **Query Results:** Found {len(result)} logs matching your criteria.\n\n⏱️ *Query executed in {processing_time:.2f} seconds*"
            st.session_state.lc_memory.save_context({"input": user_input}, {"output": content})
            return content, df_json
        else:
            # String result (count or error)
            st.session_state.lc_memory.save_context({"input": user_input}, {"output": result})
            return result, None
    
    # Handle other intents
    elif intent == "diagnosis_request":
        content = "To diagnose an error, please click the '🔧 Diagnose' button next to any error row in the results table above."
    elif intent == "upload_help":
        content = (
            "**How to Upload Logs:**\n\n"
            "1. Use the file uploader in the left sidebar\n"
            "2. Select a JSON log file (.json, .jsonl, .log, .txt)\n"
            "3. Click 'Upload & Process Logs'\n"
            "4. Wait for the indexing to complete\n"
            "5. Start asking questions about your logs!\n\n"
            "**Supported formats:** JSONL (one JSON object per line)"
        )
    elif intent == "feedback":
        content = "Thank you for your feedback! Your input helps us improve the assistant's responses."
    else:  # general_chat
        content = "Hello! I'm here to help you analyze Pega logs. Upload a log file and start asking questions about errors, patterns, or specific log entries."
    
    st.session_state.lc_memory.save_context({"input": user_input}, {"output": content})
    return content, None

@st.cache_data(show_spinner=False)

def diagnose_specific_error_llm_only(error_data_tuple):
    """Diagnose error using LLM knowledge only (no web search), masking sensitive data."""
    start_time = time.time()
    error_data = dict(error_data_tuple)
    masked_data = mask_sensitive_data(error_data)

    context = f"""
[INPUT ERROR DETAILS]
app: {masked_data.get('app', 'Unknown')}
timestamp: {masked_data.get('timestamp', 'Unknown')}
level: {masked_data.get('level', 'N/A')}
message: {masked_data.get('message', 'No message')}
exception_class: {masked_data.get('exception_class', 'N/A')}
exception_message: {masked_data.get('exception_message', 'N/A')}
stack:
{masked_data.get('stack', 'No stack trace')}
"""

    try:
        diagnosis_task = Task(
            description=(
                "You are a senior backend/SRE engineer. Read [INPUT ERROR DETAILS] and:\n"
                "1) Identify the most likely ROOT CAUSE. If a stack trace is present, point to the failing frame "
                "(class/file and line if visible), and identify the failing component (service/layer).\n"
                "2) Provide IMMEDIATE ACTIONS to fix (config change, code fix, dependency fix, infra fix), "
                "with code/config snippets where appropriate.\n"
                "3) List VALIDATION STEPS to confirm the fix (logs to check, commands, metrics, tests).\n"
                "4) Add PREVENTION strategies (alerts, retries, circuit breakers, input validation, timeouts, etc.).\n"
                "5) If information is missing, state assumptions clearly.\n\n"
                f"{context}\n\n"
                "Return a concise, actionable answer with these sections:\n"
                "### Root Cause\n"
                "### Immediate Fix\n"
                "### Validation\n"
                "### Prevention\n"
            ),
            expected_output="Actionable diagnosis with sections for Root Cause, Immediate Fix, Validation, Prevention.",
            agent=diagnosis_agent_llm
        )

        crew_diagnose = Crew(agents=[diagnosis_agent_llm], tasks=[diagnosis_task], verbose=False)
        result = crew_diagnose.kickoff()
        
        processing_time = time.time() - start_time
        return f"{str(result)}\n\n⏱️ *Diagnosis completed in {processing_time:.2f} seconds*", masked_data
    except Exception as e:
        return f"❌ Error during diagnosis: {str(e)}", masked_data


@st.cache_data(show_spinner=False)

def search_web_for_error(error_data_tuple):
    """Search web for additional solutions with working links, masking sensitive data."""
    start_time = time.time()
    error_data = dict(error_data_tuple)
    masked_data = mask_sensitive_data(error_data)
    search_query = f"{masked_data.get('exception_class', '')} {masked_data.get('message', '')[:100]}"
    try:
        search_task = Task(
            description=(
                f"Search for WORKING LINKS and solutions to this Pega error: {search_query}\n\n"
                f"Error details:\n"
                f"- Exception: {masked_data.get('exception_class', 'N/A')}\n"
                f"- Message: {masked_data.get('message', 'N/A')[:200]}\n"
                f"- App: {masked_data.get('app', 'N/A')}\n\n"
                f"REQUIREMENTS:\n"
                f"1. Find actual working URLs (https://...) for Pega solutions\n"
                f"2. Search site:community.pega.com first\n"
                f"3. Then search site:docs.pega.com\n"
                f"4. Verify each URL is complete and properly formatted\n"
                f"5. Provide brief summary of what each link contains"
            ),
            expected_output="Web search results with working links and solution summaries",
            agent=diagnosis_agent_web
        )
        crew_search = Crew(agents=[diagnosis_agent_web], tasks=[search_task], verbose=False)
        result = crew_search.kickoff()
        processing_time = time.time() - start_time
        return f"{str(result)}\n\n⏱️ *Web search completed in {processing_time:.2f} seconds*", masked_data
    except Exception as e:
        return f"❌ Error during web search: {str(e)}", masked_data

# --- Query Execution Functions ---
def execute_log_query(user_query: str):
    """Execute log query using CrewAI agents with memory context for follow-ups."""
    if not st.session_state.session_id:
        return "❌ Please upload logs first."
    
    start_time = time.time()
    sql_tool.session_id = st.session_state.session_id
    

    try:
        # Pass the query with any context directly to SQL agent
        search_task = Task(
            description=f"Create and execute OpenSearch SQL query for: '{user_query}'. Return exact tool output without any LLM processing.",
            expected_output="Raw tool execution results - return the exact data from the tool",
            agent=sql_query_builder_agent
        )
        crew_search = Crew(agents=[sql_query_builder_agent], tasks=[search_task], verbose=False)
        results = crew_search.kickoff()

        processing_time = time.time() - start_time
        raw_output = getattr(results, 'raw', results)
        if isinstance(raw_output, list):
            data = raw_output
        elif isinstance(raw_output, dict):
            data = [raw_output]
        elif isinstance(raw_output, str):
            try:
                parsed = json.loads(raw_output)
                if isinstance(parsed, list):
                    data = parsed
                elif isinstance(parsed, dict):
                    data = [parsed]
                else:
                    data = []
            except Exception:
                try:
                    parsed = ast.literal_eval(raw_output)
                    if isinstance(parsed, list):
                        data = parsed
                    elif isinstance(parsed, dict):
                        data = [parsed]
                    else:
                        data = []
                except Exception:
                    data = []
        else:
            data = []

        # If user asked for a count
        if any(keyword in user_query.lower() for keyword in ["count", "how many", "total errors", "number of errors"]):
            # Check if data contains direct count result
            if data and isinstance(data, list) and len(data) > 0:
                first_item = data[0]
                for key, value in first_item.items():
                    if 'count' in key.lower() or key == 'COUNT(*)':
                        # Return as DataFrame for table rendering
                        df = pd.DataFrame([{key: value}])
                        st.session_state.last_query_time = processing_time
                        return df
                # If no direct count field, create dataframe and count errors
                df = create_results_dataframe(data)
                if not df.empty and 'level' in df.columns:
                    if 'error' in user_query.lower():
                        error_count = (df['level'] == 'ERROR').sum()
                        df_count = pd.DataFrame([{"error_count": error_count}])
                        st.session_state.last_query_time = processing_time
                        return df_count
                    else:
                        df_count = pd.DataFrame([{"log_count": len(df)}])
                        st.session_state.last_query_time = processing_time
                        return df_count
                else:
                    df_count = pd.DataFrame([{"log_count": len(data)}])
                    st.session_state.last_query_time = processing_time
                    return df_count
            else:
                df_count = pd.DataFrame([{"log_count": 0}])
                st.session_state.last_query_time = processing_time
                return df_count

        # For non-count queries, proceed as before
        if not data or not isinstance(data, list) or (isinstance(data, list) and not data):
            return f" Query successful, but no matching records found.\n⏱️ *Query executed in {processing_time:.2f} seconds*"

        df = create_results_dataframe(data)

        # Store timing in session state for display
        st.session_state.last_query_time = processing_time

        return df

    except Exception as e:
        return f"❌ Error executing query: {str(e)}"


def render_table_with_inline_buttons(df: pd.DataFrame, message_idx: int):
    """Render logs table and show Diagnose / Web buttons ONLY for ERROR rows without opening new tabs. Show masked data next to buttons."""
    if df is None or df.empty:
        st.info("No data to display.")
        return

    hidden_cols = ['Actions', 'message_raw']
    visible_cols = [c for c in df.columns if c not in hidden_cols]
    priority = ['timestamp','app','level','message','message.event.caseId','stack','RequestorId','CorrelationId','exception_class','exception_message']
    ordered_cols = [c for c in priority if c in visible_cols] + [c for c in visible_cols if c not in priority]

    # Build static HTML table (no action columns)
    html_rows = []
    for idx, row in df.iterrows():
        cells = []
        for col in ordered_cols:
            val = row.get(col, '')
            sval = '' if val is None else str(val)
            if col == 'level':
                sval = f"<span class='level-badge-{html.escape(sval)}'>{html.escape(sval)}</span>"
            else:
                sval = html.escape(sval)
            cls = 'message' if col=='message' else ('stack' if col=='stack' else '')
            cells.append(f"<td class='{cls}'>{sval}</td>")
        html_rows.append(f"<tr>{''.join(cells)}</tr>")

    header_cells = [f"<th>{html.escape(c)}</th>" for c in ordered_cols]
    table_html = f"<div class='log-scroll-wrapper'><table class='log-html-table'><thead><tr>{''.join(header_cells)}</tr></thead><tbody>{''.join(html_rows)}</tbody></table></div>"
    st.markdown(table_html, unsafe_allow_html=True)

    # Inline action buttons only for ERROR rows
    error_rows = df[df['level'].astype(str).str.upper() == 'ERROR'] if 'level' in df.columns else pd.DataFrame()
    if not error_rows.empty:
        st.markdown("#### Error Actions (Diagnose / Web Search)")
        for ridx, row in error_rows.iterrows():
            short_msg = str(row.get('message', ''))[:140].replace('\n', ' ')
            timestamp = row.get('timestamp', '')
            app = row.get('app', '')
            masked_data = mask_sensitive_data(row.to_dict())
            with st.expander("🔒 Masked Data Sent to LLM", expanded=False):
                st.json(masked_data, expanded=False)
            container = st.container()
            with container:
                cols = st.columns([6, 1.2, 1.4])
                with cols[0]:
                    st.markdown(f"**{timestamp}** | `{app}` | {row.get('level','')}<br/>{html.escape(short_msg)}", unsafe_allow_html=True)
                with cols[1]:
                    if st.button("🔧 Diagnose", key=f"diag_{message_idx}_{ridx}"):
                        with st.spinner('🔬 Running diagnosis...'):
                            diag_result, masked = diagnose_specific_error_llm_only(tuple(row.to_dict().items()))
                        msg = f"### 🔬 Diagnosis Result\n\n**For Error:** `{short_msg}`\n\n---\n\n{diag_result}"
                        st.session_state.messages.append({'role':'assistant','content':msg,'id':f'diag_{message_idx}_{ridx}','diagnosis_error':row.to_dict(), 'masked_data': masked})
                        st.rerun()
                with cols[2]:
                    if st.button("🌐 Search Web", key=f"web_{message_idx}_{ridx}"):
                        with st.spinner('🌐 Searching the web for solutions...'):
                            web_result, masked = search_web_for_error(tuple(row.to_dict().items()))
                        msg = f"### 🌐 Web Search Results\n\n**For Error:** `{short_msg}`\n\n---\n\n{web_result}"
                        st.session_state.messages.append({'role':'assistant','content':msg,'id':f'web_{message_idx}_{ridx}','diagnosis_error':row.to_dict(), 'masked_data': masked})
                        st.rerun()


# --- Main Streamlit App ---
def main():
    st.title("AI Log Troubleshooter")
    if not st.session_state.messages:
        welcome_msg = (
            """Welcome to AI Log Troubleshooter!

            What this app can do:

            - Upload and Analyze Pega Logs: Upload your Pega log files and interactively explore them.
            - Ask Natural Language Questions: Query your logs using plain English (e.g., 'Show all errors from today', 'How many times did login fail?').
            - Smart Log Querying: Get targeted results with relevant columns, filters, and groupings. The assistant understands time ranges, log levels, keywords, and more.
            - Follow-up Questions: Ask follow-up questions about previous results (e.g., 'How many errors in the last result?', 'Group by app').
            - Root Cause Analysis: Click 'Diagnose' on any error row to get an AI-powered root cause and recommended actions.
            - Web Search for Solutions: Instantly search Pega Community and technical sites for solutions to specific errors.
            - Feedback: Rate answers and provide feedback to help improve the assistant.

            How to use:
            1. Upload a log file using the sidebar.
            2. Ask questions about your logs in the chat below.
            3. Explore results in tables, use filters, and click 'Diagnose' or 'Search Web' for deeper insights.

            *Your data is masked before being sent to AI models for privacy.*
        """
        )
        st.session_state.messages.append({"role": "assistant", "content": welcome_msg, "id": "initial_msg"})
    
    with st.sidebar:
        st.header("📁 Upload Logs")
        uploaded_file = st.file_uploader("Choose a log file", type=['json', 'jsonl', 'log', 'txt'])
        
        if uploaded_file is not None:
            if st.button("Upload & Process Logs", type="primary"):
                with st.spinner("Uploading and indexing logs..."):
                    upload_result = upload_logs_from_chat(uploaded_file)
                    st.session_state.messages.append({"role": "assistant", "content": upload_result, "id": str(uuid.uuid4())})
                    st.rerun()
        
        if st.session_state.session_id:
            st.header("📊 Session Info")
            st.info(f"""
            **Session ID:** `{st.session_state.session_id[:8]}...`
            **Total Logs in File:** `{st.session_state.total_logs:,}`
            **Successfully Indexed:** `{st.session_state.indexed_logs:,}`
            """)
            
            if st.button("🗑️ Clear Chat & Session"):
                st.session_state.messages = []
                st.session_state.session_id = None
                st.session_state.total_logs = 0
                st.session_state.indexed_logs = 0
                st.session_state.diagnosis_cache = {}
                st.session_state.feedback_open_for = {}
                st.session_state.feedback_text = {}
                st.rerun()

    for idx, msg in enumerate(st.session_state.messages): 
        avatar = "alamaticz_logo.png" if msg["role"] == "assistant" else "user"
        with st.chat_message(msg["role"], avatar=avatar):
            st.markdown(msg["content"])
            if "dataframe" in msg and msg["dataframe"]:
                try:
                    df = pd.read_json(StringIO(msg["dataframe"]))
                    render_table_with_inline_buttons(df, idx)
                except Exception as e:
                    st.error(f"⚠️ Could not render table: {e}")

            if msg["role"] == "assistant" and msg.get("id") != "initial_msg":
                col1, col2, _ = st.columns([1, 1, 10])
                with col1:
                    if st.button("👍", key=f"feedback_up_{idx}_{msg['id']}"):
                        st.session_state.feedback_open_for[msg['id']] = 'up'
                        st.rerun()
                with col2:
                    if st.button("👎", key=f"feedback_down_{idx}_{msg['id']}"):
                        st.session_state.feedback_open_for[msg['id']] = 'down'
                        st.rerun()

                mode = st.session_state.feedback_open_for.get(msg['id'])
                if mode in ('up', 'down'):
                    label = "What did you like?" if mode == 'up' else "What could be improved?"
                    st.session_state.feedback_text[msg['id']] = st.text_area(
                        label,
                        key=f"feedback_text_{idx}_{msg['id']}",
                        placeholder="Your feedback helps improve the assistant’s answers…"
                    )
                    submit_cols = st.columns([1, 1, 10])
                    with submit_cols[0]:
                        if st.button("Submit", key=f"feedback_submit_{idx}_{msg['id']}"):
                            user_comment = st.session_state.feedback_text.get(msg['id'], "").strip()
                            ok, info = save_feedback(
                                feedback_type="positive" if mode == 'up' else "negative",
                                session_id=st.session_state.session_id,
                                message_id=msg['id'],
                                message_content=msg['content'],
                                user_comment=user_comment,
                                full_conversation=st.session_state.messages,
                                attached_dataframe_json=msg.get("dataframe")
                            )
                            # Prepare modal content
                            if ok:
                                st.session_state.feedback_modal_message = f"Thanks for your feedback! Saved to S3 as: {info}"
                                st.session_state.feedback_modal_error = False
                            else:
                                st.session_state.feedback_modal_message = f"Could not save feedback to S3. {info}. Please check AWS credentials/permissions and bucket region."
                                st.session_state.feedback_modal_error = True
                            st.session_state.feedback_modal_open = True

                            st.session_state.feedback_open_for[msg['id']] = None
                            st.session_state.feedback_text[msg['id']] = ""
                            st.rerun()
                    with submit_cols[1]:
                        if st.button("Cancel", key=f"feedback_cancel_{idx}_{msg['id']}"):
                            st.session_state.feedback_open_for[msg['id']] = None
                            st.session_state.feedback_text[msg['id']] = ""
                            st.rerun()

    if prompt := st.chat_input("Ask a question about your logs..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant", avatar="alamaticz_logo.png"):
            sql_tool.session_id = st.session_state.session_id
            thinking = st.empty()
            thinking.markdown("<div class='lt-thinking-box'><div class='lt-spinner'></div><div>Thinking...</div></div>", unsafe_allow_html=True)
            
            # Show debug info immediately
            debug_container = st.empty()
            
            try:
                content, df_json = orchestrator_handle_user_input(prompt)
            finally:
                thinking.empty()
                
            st.markdown(content)
            msg = {"role": "assistant", "content": content, "id": str(uuid.uuid4())}
            if df_json:
                msg["dataframe"] = df_json
            st.session_state.messages.append(msg)
            st.rerun()
if __name__ == "__main__":
    main()