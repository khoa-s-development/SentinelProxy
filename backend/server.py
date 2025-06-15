import os, threading, sys, random, time, csv, logging
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import google.generativeai as genai
from io import StringIO

load_dotenv()

genai_api = os.getenv("GEMINI_API_KEY")

logging.basicConfig(
    level = logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(message)s',
    handlers = [
        logging.FileHandler('data/log/server.log', encoding = 'utf-8'),
        logging.StreamHandler(stream = sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def load_server_config():
    config = {"backend_ip": "192.168.1.1", "port": "3107", "X-Auth-Token": "default"}
    config_path = "backendcfg.txt"
    try:
        if not os.path.exists(config_path):
            logger.warning("Config file not found at %s, using default", config_path)
            return config
        with open(config_path, "r") as f:
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    if key == "backend_ip":
                        config["backend_ip"] = value.strip()
                    elif key == "port":
                        config["port"] = value.strip()
                    elif key == "X-Auth-Token":
                        config["X-Auth-Token"] = value.strip()
        logger.info("Loaded config in file: IP = %s, port = %d, X-Auth-Token = %s", config["backend_ip"], config["port"], config["X-Auth-Token"])
    except Exception as e:
        logger.error("Error loading config file: %s, using default configuration", str(e))
    return config

config = load_server_config()

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECERT_KEY")
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_orgins = "*", async_mode = "threading")
logger.info("SocketIO initialized with threading")

server_start_time = datetime.now(timezone.utc)

client = genai.Client(api_key=genai_api)

def handleAIRequest(req):
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=req
    )
    return response.text

@app.route("/postPacket", methods = ["POST"])
async def handlePacket():
    data = request.get_json()
    packet_size = data.get("packet_size")
    packet_rate = data.get("packet_rate")
    protocol_type = data.get("protocol_type")
    connection_state = data.get("connection_state")
    payload_pattern = data.get("payload_pattern")
    if not packet_size or not packet_rate or not protocol_type or not connection_state or not payload_pattern:
        return jsonify({"status": "error", "message": "Error while handling request! Please check your request."})
    else:
        aireq = f'REQUEST CHECK: packet_size = {packet_size}, packet_rate = {packet_rate}, protocol_type = {protocol_type}, connection_state = {connection_state}, payload_pattern = {payload_pattern}'
        result = await handleAIRequest(aireq)
        return jsonify({"status": "sucess", "message": result})
        
