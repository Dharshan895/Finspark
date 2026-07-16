import os
import json
import asyncio
import struct
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
from backend.generator import LogGenerator, USERS
from backend.model import UEBAModel
from backend.soar import SOAREngine
from backend.pqc_vault import PQCQuantumSafeVault

app = FastAPI(title="SentinelIQ Backend", version="1.0.0")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core Instances
generator = LogGenerator()
model = UEBAModel()
soar_engine = SOAREngine()
pqc_vault = PQCQuantumSafeVault()

# Audit Log Encryption Setup
# Generate Fernet key (AES-128/256 symmetric encryption)
# NOTE: This AES-based encryption is a placeholder for a post-quantum Kyber/lattice-based encryption.
# In a production environment, this would be swapped out for post-quantum algorithms (e.g. ML-KEM)
# via the liboqs-python library to ensure security against future cryptographic threats.
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)
AUDIT_LOG_PATH = "audit_trail.enc"

# Store some sample secrets in PQC vault at startup
for uid in list(USERS.keys())[:5]:
    pqc_vault.store_secret(uid, "api_secret_key", f"pqc_sk_{uid}_xyz1024_hash_sig")
    pqc_vault.store_secret(uid, "db_password", f"db_pass_{uid}_super_secret_banking")

# WebSocket Connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # We broadcast as text containing JSON
        data = json.dumps(message)
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                pass

manager = ConnectionManager()

# Queue for incoming events to be processed and streamed (demo attacks push here)
event_queue = asyncio.Queue()

def encrypt_and_log_audit(event):
    """
    Encrypts a flagged event with AES-256 (Fernet) and appends it to a local binary file.
    """
    event_str = json.dumps(event)
    encrypted_bytes = fernet.encrypt(event_str.encode("utf-8"))
    
    # Write length of encrypted bytes as 4-byte big-endian int, then the bytes
    with open(AUDIT_LOG_PATH, "ab") as f:
        f.write(struct.pack(">I", len(encrypted_bytes)))
        f.write(encrypted_bytes)

def read_and_decrypt_audit():
    """
    Reads the encrypted binary audit log, decrypts each record, and returns a list of dictionaries.
    """
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
        
    events = []
    with open(AUDIT_LOG_PATH, "rb") as f:
        while True:
            len_bytes = f.read(4)
            if not len_bytes or len(len_bytes) < 4:
                break
            length = struct.unpack(">I", len_bytes)[0]
            encrypted_bytes = f.read(length)
            if len(encrypted_bytes) < length:
                break
            try:
                decrypted_bytes = fernet.decrypt(encrypted_bytes)
                events.append(json.loads(decrypted_bytes.decode("utf-8")))
            except Exception as e:
                print(f"Decryption error in audit trail: {e}")
    return events

# Background task generating normal logs continuously and pushing to queue
async def background_log_generator():
    await asyncio.sleep(2.0) # Wait for model to train
    while True:
        # If queue is empty, generate a normal event
        if event_queue.empty():
            normal_event = generator.generate_event()
            await event_queue.put(normal_event)
        await asyncio.sleep(1.2) # Generate log every 1.2s

# Processor task: reads events, scores them, updates SOAR, writes audit, broadcasts
async def event_processor():
    while True:
        event = await event_queue.get()
        
        # Check if user is already locked by SOAR
        user_id = event["user_id"]
        role = event["role"]
        current_state = soar_engine.get_user_state(user_id, role)
        
        if current_state["status"] == "locked":
            # If user is locked, restrict database, config change, and exports
            if event["action"] in ["db_query", "config_change", "data_export"]:
                event["status"] = "blocked"
                event["risk_score"] = 99
                event["explanation"] = f"SOAR Alert: Access BLOCKED because user account '{user_id}' is in a Locked state."
                event["mitre_techniques"] = [{"id": "T1562", "name": "SOAR Rule: Action Blocked", "tactic": "Response Automation"}]
                event["user_status"] = "locked"
                
                # Broadcast blocked event immediately
                await manager.broadcast(event)
                event_queue.task_done()
                continue

        # Score event using ML + Heuristic rules
        risk_score, explanation, mitre_mappings = model.score_event(event)
        
        # Evaluate with SOAR Engine
        state, triggered_actions = soar_engine.evaluate_event(event, risk_score, explanation, mitre_mappings)
        
        # Enrich event details
        event["risk_score"] = risk_score
        event["explanation"] = explanation
        event["mitre_techniques"] = mitre_mappings
        event["user_status"] = state["status"]
        if triggered_actions:
            event["soar_actions"] = triggered_actions
            
        # Log to local encrypted audit trail if risk score is high
        if risk_score >= 50:
            encrypt_and_log_audit(event)
            
        # Broadcast real-time event to clients
        await manager.broadcast(event)
        event_queue.task_done()

@app.on_event("startup")
async def startup_event():
    # 1. Train Model
    print("Generating baseline for model training...")
    baseline = generator.generate_baseline(10000)
    model.train(baseline)
    
    # 2. Start Background tasks
    asyncio.create_task(background_log_generator())
    asyncio.create_task(event_processor())
    print("SentinelIQ Engine started successfully.")

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We keep the connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/trigger-attack")
async def trigger_attack(payload: dict):
    attack_type = payload.get("attack_type")
    if not attack_type or attack_type not in [1, 2, 3, 4, 5]:
        raise HTTPException(status_code=400, detail="Invalid attack_type. Must be between 1 and 5.")
        
    # Generate the sequence of malicious logs
    sequence = {
        1: generator.trigger_attack_1,
        2: generator.trigger_attack_2,
        3: generator.trigger_attack_3,
        4: generator.trigger_attack_4,
        5: generator.trigger_attack_5,
    }[attack_type]()
    
    # Push sequence items into queue sequentially
    for evt in sequence:
        await event_queue.put(evt)
        
    return {"status": "triggered", "attack_type": attack_type, "events_injected": len(sequence)}

@app.get("/api/users/risk")
def get_user_risks():
    return soar_engine.get_all_states()

@app.get("/api/soar/incidents")
def get_incidents():
    return soar_engine.get_soc_queue()

@app.post("/api/unlock-user/{user_id}")
def unlock_user(user_id: str):
    success = soar_engine.unlock_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found in UEBA memory database.")
    return {"status": "success", "message": f"User {user_id} account unlocked successfully."}

@app.get("/api/audit-trail")
def get_audit_trail():
    events = read_and_decrypt_audit()
    return {
        "status": "decrypted",
        "file_size_bytes": os.path.exists(AUDIT_LOG_PATH) and os.path.getsize(AUDIT_LOG_PATH) or 0,
        "records_count": len(events),
        "events": events[::-1] # return newest first
    }

@app.get("/api/vault/status")
def get_vault_status():
    return pqc_vault.get_vault_status()
