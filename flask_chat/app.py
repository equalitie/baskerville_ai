import logging
import os
import uuid
import psycopg
from flask import Flask, request, jsonify, render_template_string, make_response, Response, redirect
import markdown
import json

from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain_postgres import PostgresChatMessageHistory
from langchain.callbacks.base import BaseCallbackHandler
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits.sql.base import create_sql_agent
from langchain_community.agent_toolkits.sql.toolkit import SQLDatabaseToolkit
from langchain.prompts import PromptTemplate
from openai import OpenAI
from langchain_community.tools.sql_database.tool import QuerySQLDataBaseTool
from langchain.tools import tool
from langchain.agents import initialize_agent, AgentType
from langchain.callbacks.base import BaseCallbackHandler

import re

from strings import PROMPT_TEMPLATE, FEATURE_DESCRIPTIONS, CATEGORICAL_FEATURE_DESCRIPTIONS, EXPLANATION_RULES

# --- ENV ---
postgres_connection = {
    'host': os.environ.get('POSTGRES_HOST'),
    'user': os.environ.get('POSTGRES_USER'),
    'password': os.environ.get('POSTGRES_PASSWORD'),
    'dbname': os.environ.get('POSTGRES_DATABASE_NAME'),
    'port': int(os.environ.get('POSTGRES_PORT'))
}
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# --- CONFIG ---
HARD_PASSWORD = "Baskerville2025"

from langchain.tools import tool

class PatchedSQLDatabaseToolkit(SQLDatabaseToolkit):
    def get_tools(self):
        tools = super().get_tools()
        return [t for t in tools if t.name != "sql_db_query_checker"]

def ip_exists(ip, conn):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM challenge_command_history WHERE ip_address = %s LIMIT 1", (ip,))
        res = cur.fetchone() is not None
        logger.info(f'ip_exists: {res}')
        return res

def get_logger(name, logging_level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.setLevel(logging_level)
    logger.propagate = False  # не отдаём в Flask logger
    if not logger.handlers:
        formatter = logging.Formatter(
            '%(asctime)s %(name)s.%(funcName)s +%(lineno)s: %(levelname)-8s'
            ' [%(process)d] %(message)s'
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    return logger

logging.basicConfig(level=logging.DEBUG, force=True)

logger = get_logger(
    __name__,
    logging_level=logging.DEBUG
)

class DebugHandler(BaseCallbackHandler):
    def on_llm_start(self, serialized, prompts, **kwargs):
        # logger.info(f"\n=== LLM START ===\n{prompts}\n")
        pass

    def on_llm_end(self, response, **kwargs):
        # logger.info(f"\n=== LLM END ===\n{response}\n")
        pass

    def on_tool_end(self, output, **kwargs):
        # logger.info(f"\n[TOOL END]\n{output}\n")
        pass

    def on_agent_action(self, action, **kwargs):
        logger.info(f"\n[AGENT ACTION] {action}\n")
        pass

    def on_agent_finish(self, finish, **kwargs):
        # logger.info(f"\n[AGENT FINISH] {finish}\n")
        pass


from openai import RateLimitError
import time

class ChatOpenAIWithRetry(ChatOpenAI):
    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        retries = 5
        for i in range(retries):
            try:
                return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)
            except RateLimitError:
                wait = min(60, 2 ** i)
                print(f"[WARN] Rate limit hit. Retrying in {wait} seconds...")
                time.sleep(wait)
        raise Exception("Max retries exceeded in ChatOpenAIWithRetry")

# ======= SQL Agent =======
def init_sql_agent():
    db_url = f"postgresql+psycopg://{postgres_connection['user']}:{postgres_connection['password']}@{postgres_connection['host']}:{postgres_connection['port']}/{postgres_connection['dbname']}"
    db = SQLDatabase.from_uri(db_url, include_tables=["hostname", "sessions", "challenge_command_history"])

    llm_for_sql = ChatOpenAIWithRetry(
        model="gpt-4o-mini",
        temperature=0,
        openai_api_key=OPENAI_API_KEY
    )

    toolkit = PatchedSQLDatabaseToolkit(db=db, llm=llm_for_sql)

    system_prompt = PromptTemplate(
        template=PROMPT_TEMPLATE,
        input_variables=["input", "agent_scratchpad", "dialect", "top_k", "table_info","FEATURE_DESCRIPTIONS",
        "CATEGORICAL_FEATURE_DESCRIPTIONS", "EXPLANATION_RULES"]
    )

    handler = DebugHandler()
    agent = create_sql_agent(
        llm=llm_for_sql,
        toolkit=toolkit,
        verbose=True,
        agent_type="openai-tools",
        agent_executor_kwargs={
            "handle_parsing_errors": True
        },
        max_iterations = 50,
        prompt=system_prompt.partial(
            FEATURE_DESCRIPTIONS=FEATURE_DESCRIPTIONS,
            CATEGORICAL_FEATURE_DESCRIPTIONS=CATEGORICAL_FEATURE_DESCRIPTIONS,
            EXPLANATION_RULES=EXPLANATION_RULES,
            top_k=5
        ),
        callbacks=[handler]
    )

    return agent

sql_agent = init_sql_agent()

app = Flask(__name__)

client = OpenAI(api_key=OPENAI_API_KEY)

# --- Auth helper ---
def check_auth():
    return request.cookies.get("auth_ok") == "1"

# --- Session ID helper ---
def get_or_create_session_id():
    session_id = request.cookies.get("session_id")
    if session_id:
        try:
            uuid.UUID(session_id)
            return session_id
        except ValueError:
            pass
    return str(uuid.uuid4())

# --- Memory ---
def get_memory(session_id: str):
    conn = psycopg.connect(
        host=postgres_connection['host'],
        user=postgres_connection['user'],
        password=postgres_connection['password'],
        dbname=postgres_connection['dbname'],
        port=postgres_connection['port']
    )
    history = PostgresChatMessageHistory(
        "chat_history",
        session_id,
        sync_connection=conn
    )
    memory = ConversationBufferMemory(
        memory_key="chat_history",
        chat_memory=history,
        return_messages=True
    )
    return memory

def load_html(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

# --- Stream handler ---
class StreamHandler(BaseCallbackHandler):
    def __init__(self):
        self.tokens = []
    def on_llm_new_token(self, token: str, **kwargs):
        self.tokens.append(token)

@app.route("/health")
def health():
    return "OK", 200

# --- Login page ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == HARD_PASSWORD:
            resp = make_response(redirect("/"))
            resp.set_cookie("auth_ok", "1", max_age=60*60*24*7, httponly=True, samesite="None", secure=True)
            return resp
        else:
            return "<h3>Wrong password</h3>", 403

    html = load_html("templates/login.html")
    return html


# ======= Универсальный чат =======
@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    user_input = data.get("message", "")

    db_keywords = [
        "ip", "ip_address", "challenge", "hostname", "sessions", "host_name", "created_at",
        "database", "в базе", "база"
    ]

    # if any(kw.lower() in user_input.lower() for kw in db_keywords):
    if True:
        try:
            if not isinstance(user_input, str):
                user_input = str(user_input)

            ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", user_input)

            if ip_match:
                ip = ip_match.group(0)
                logger.info('ip detected: {}'.format(ip))
                with psycopg.connect(**postgres_connection) as conn:
                    if not ip_exists(ip, conn):
                        return markdown.markdown("IP not found in the database. Only data from the last 3 days is stored.")

            response = sql_agent.invoke({"input": user_input}, verbose=True, callbacks=[DebugHandler()])
            html_content = markdown.markdown(response["output"], extensions=["fenced_code", "tables"])

            return html_content

        except Exception as e:
            return jsonify({"response": f"SQL Agent error: {str(e)}"}), 500
    else:
        response = client.chat.completions.create(
            model="gpt-4o",
            # model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful AI assistant."},
                {"role": "user", "content": user_input}
            ]
        )
        return response.choices[0].message.content

# --- Index (protected) ---
@app.route("/")
def index():
    if not check_auth():
        return redirect("/login")

    session_id = get_or_create_session_id()
    html = load_html("templates/index.html")
    resp = make_response(render_template_string(html))
    resp.set_cookie(
        "session_id",
        session_id,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        samesite="None",  # 🔥
        secure=True  # 🔥
    )
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
