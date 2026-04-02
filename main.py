# ═══════════════════════════════════════════════════════════════
#  AquaSmart Backend — FastAPI
#  aquasmart/backend/main.py
#  Roles: público | operario | administrador
#  1 tanque de reserva
# ═══════════════════════════════════════════════════════════════
import os, asyncio, json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorClient
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

# ── Config ───────────────────────────────────────────────────────
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
SECRET_KEY  = os.getenv("SECRET_KEY", "aquasmart_dev_secret_2024")
ALGORITHM   = "HS256"
TOKEN_EXP   = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440))
API_KEY     = os.getenv("API_KEY", "aquasmart_esp32_key_2024")

# ── App ───────────────────────────────────────────────────────────
app = FastAPI(title="AquaSmart API", version="1.0.0",
              description="Sistema de Telemetría — Lérida, Tolima")

app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])

# ── MongoDB ───────────────────────────────────────────────────────
mongo = AsyncIOMotorClient(MONGODB_URL)
db    = mongo.aquasmart

# ── Auth ──────────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2  = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Usuarios del sistema (en producción, guardarlos en MongoDB)
USERS = {
    "operario": {
        "username": "operario",
        "hashed_password": pwd_ctx.hash(os.getenv("OPERATOR_PASSWORD", "operario123")),
        "role": "operator",
        "label": "Operario",
    },
    "admin": {
        "username": "admin",
        "hashed_password": pwd_ctx.hash(os.getenv("ADMIN_PASSWORD", "admin2024")),
        "role": "admin",
        "label": "Administrador",
    },
}

# ── Estado global del sistema ─────────────────────────────────────
class SystemState:
    def __init__(self):
        self.thresholds = {"low": 30.0, "high": 90.0}
        self.auto_mode  = True
        self.tank_name  = "Tanque Principal"

system = SystemState()


# ═══════════════════════════════════════════════════════════════════
#  WEBSOCKET MANAGER
# ═══════════════════════════════════════════════════════════════════
class WSManager:
    def __init__(self):
        self.frontends: list[WebSocket] = []
        self.esp32: Optional[WebSocket] = None

    async def add_frontend(self, ws: WebSocket):
        await ws.accept()
        self.frontends.append(ws)

    def remove_frontend(self, ws: WebSocket):
        if ws in self.frontends:
            self.frontends.remove(ws)

    async def set_esp32(self, ws: WebSocket):
        self.esp32 = ws

    def clear_esp32(self):
        self.esp32 = None

    async def broadcast(self, data: dict):
        payload = json.dumps(data)
        dead = []
        for ws in self.frontends:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.frontends.remove(ws)

    async def cmd_esp32(self, cmd: dict) -> bool:
        if not self.esp32:
            return False
        try:
            await self.esp32.send_text(json.dumps(cmd))
            return True
        except Exception:
            self.clear_esp32()
            return False

ws_manager = WSManager()


# ═══════════════════════════════════════════════════════════════════
#  MODELOS PYDANTIC
# ═══════════════════════════════════════════════════════════════════
class TelemetryIn(BaseModel):
    level:    float
    pump:     bool
    valve:    bool
    temp:     float = 18.0
    flow:     float = 0.0
    pressure: float = 0.0

class AlertIn(BaseModel):
    alert_type: str   # "low" | "high" | "offline"
    level:      float
    msg:        str = ""

class PumpCmd(BaseModel):
    on: bool

class ValveCmd(BaseModel):
    open: bool

class ThresholdUpdate(BaseModel):
    low:  float = Field(..., ge=5,  le=50)
    high: float = Field(..., ge=55, le=98)

class AutoModeUpdate(BaseModel):
    enabled: bool

class RenameUpdate(BaseModel):
    name: str

class Token(BaseModel):
    access_token: str
    token_type:   str
    role:         str
    label:        str
    username:     str


# ═══════════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ═══════════════════════════════════════════════════════════════════
def make_token(data: dict) -> str:
    p = {**data, "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXP)}
    return jwt.encode(p, SECRET_KEY, algorithm=ALGORITHM)

async def get_user(token: str = Depends(oauth2)) -> dict:
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username not in USERS:
            raise HTTPException(401, "Token inválido")
        return USERS[username]
    except JWTError:
        raise HTTPException(401, "Token inválido o expirado")

async def need_operator(user=Depends(get_user)) -> dict:
    if user["role"] not in ("operator", "admin"):
        raise HTTPException(403, "Se requiere rol operario o superior")
    return user

async def need_admin(user=Depends(get_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Solo administradores")
    return user

def check_esp32_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(403, "API Key del ESP32 inválida")


# ═══════════════════════════════════════════════════════════════════
#  ENDPOINTS — AUTENTICACIÓN
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/auth/login", response_model=Token, tags=["Auth"])
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = USERS.get(form.username)
    if not user or not pwd_ctx.verify(form.password, user["hashed_password"]):
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    token = make_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer",
            "role": user["role"], "label": user["label"], "username": user["username"]}

@app.get("/api/auth/me", tags=["Auth"])
async def me(user=Depends(get_user)):
    return {"username": user["username"], "role": user["role"], "label": user["label"]}


# ═══════════════════════════════════════════════════════════════════
#  ENDPOINTS — PÚBLICOS (sin autenticación)
# ═══════════════════════════════════════════════════════════════════
@app.get("/api/tank", tags=["Público"])
async def get_tank():
    """Estado actual del tanque — accesible por todos."""
    doc = await db.telemetry.find_one(
        {"tank_id": 1}, {"_id": 0}, sort=[("created_at", -1)]
    )
    if doc and "created_at" in doc:
        doc["created_at"] = doc["created_at"].isoformat()
    return {
        "tank":       doc or {},
        "tank_name":  system.tank_name,
        "thresholds": system.thresholds,
        "auto_mode":  system.auto_mode,
        "esp32_online": ws_manager.esp32 is not None,
    }

@app.get("/api/alerts", tags=["Público"])
async def get_alerts(limit: int = 50):
    alerts = []
    async for doc in db.alerts.find({}, {"_id": 0}).sort("created_at", -1).limit(limit):
        if "created_at" in doc:
            doc["created_at"] = doc["created_at"].isoformat()
        alerts.append(doc)
    return {"alerts": alerts}

@app.get("/api/tank/history", tags=["Público"])
async def get_history(hours: int = 24):
    since = datetime.utcnow() - timedelta(hours=hours)
    readings = []
    async for doc in db.telemetry.find(
        {"tank_id": 1, "created_at": {"$gte": since}}, {"_id": 0}
    ).sort("created_at", 1).limit(2000):
        if "created_at" in doc:
            doc["created_at"] = doc["created_at"].isoformat()
        readings.append(doc)
    return {"readings": readings, "count": len(readings)}

@app.get("/", tags=["Sistema"])
async def health():
    return {
        "service": "AquaSmart API", "status": "ok", "version": "1.0.0",
        "esp32_online": ws_manager.esp32 is not None,
        "frontend_clients": len(ws_manager.frontends),
        "thresholds": system.thresholds,
        "auto_mode": system.auto_mode,
    }


# ═══════════════════════════════════════════════════════════════════
#  ENDPOINTS — OPERARIO (operario + admin)
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/control/pump", tags=["Operario"])
async def control_pump(cmd: PumpCmd, user=Depends(need_operator)):
    action = "pump_on" if cmd.on else "pump_off"
    sent   = await ws_manager.cmd_esp32({"type": "command", "action": action})
    await ws_manager.broadcast({"type": "pump_update", "pump": cmd.on})
    await db.action_logs.insert_one({
        "user": user["username"], "action": f"Bomba {'encendida' if cmd.on else 'apagada'}",
        "created_at": datetime.utcnow()
    })
    return {"status": "ok", "pump": cmd.on, "esp32_reached": sent}

@app.post("/api/control/valve", tags=["Operario"])
async def control_valve(cmd: ValveCmd, user=Depends(need_operator)):
    action = "valve_open" if cmd.open else "valve_close"
    sent   = await ws_manager.cmd_esp32({"type": "command", "action": action})
    await ws_manager.broadcast({"type": "valve_update", "valve": cmd.open})
    await db.action_logs.insert_one({
        "user": user["username"], "action": f"Compuerta {'abierta' if cmd.open else 'cerrada'}",
        "created_at": datetime.utcnow()
    })
    return {"status": "ok", "valve": cmd.open, "esp32_reached": sent}


# ═══════════════════════════════════════════════════════════════════
#  ENDPOINTS — ADMIN EXCLUSIVOS
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/control/thresholds", tags=["Admin"])
async def set_thresholds(req: ThresholdUpdate, _=Depends(need_admin)):
    if req.low >= req.high:
        raise HTTPException(400, "Umbral bajo debe ser menor al alto")
    system.thresholds = {"low": req.low, "high": req.high}
    await ws_manager.cmd_esp32({
        "type": "command", "action": "set_thresholds",
        "low": req.low, "high": req.high
    })
    await ws_manager.broadcast({"type": "thresholds_update", "thresholds": system.thresholds})
    await db.config.update_one({"key": "thresholds"},
        {"$set": {"value": system.thresholds, "updated_at": datetime.utcnow()}}, upsert=True)
    await db.action_logs.insert_one({
        "user": "admin", "action": f"Umbrales → bajo={req.low}%, alto={req.high}%",
        "created_at": datetime.utcnow()
    })
    return {"status": "ok", "thresholds": system.thresholds}

@app.post("/api/control/auto-mode", tags=["Admin"])
async def set_auto_mode(req: AutoModeUpdate, _=Depends(need_admin)):
    system.auto_mode = req.enabled
    await ws_manager.cmd_esp32({"type": "command", "action": "set_auto_mode", "enabled": req.enabled})
    await ws_manager.broadcast({"type": "auto_mode_update", "auto_mode": req.enabled})
    await db.action_logs.insert_one({
        "user": "admin", "action": f"Modo {'automático' if req.enabled else 'manual'} activado",
        "created_at": datetime.utcnow()
    })
    return {"status": "ok", "auto_mode": system.auto_mode}

@app.post("/api/control/rename", tags=["Admin"])
async def rename_tank(req: RenameUpdate, _=Depends(need_admin)):
    if not req.name.strip():
        raise HTTPException(400, "El nombre no puede estar vacío")
    system.tank_name = req.name.strip()
    await ws_manager.broadcast({"type": "tank_renamed", "name": system.tank_name})
    await db.action_logs.insert_one({
        "user": "admin", "action": f"Tanque renombrado a '{system.tank_name}'",
        "created_at": datetime.utcnow()
    })
    return {"status": "ok", "name": system.tank_name}

@app.delete("/api/alerts", tags=["Admin"])
async def clear_alerts(_=Depends(need_admin)):
    result = await db.alerts.delete_many({})
    return {"status": "ok", "deleted": result.deleted_count}

@app.get("/api/logs", tags=["Admin"])
async def get_logs(limit: int = 100, _=Depends(need_admin)):
    logs = []
    async for doc in db.action_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(limit):
        if "created_at" in doc:
            doc["created_at"] = doc["created_at"].isoformat()
        logs.append(doc)
    return {"logs": logs}


# ═══════════════════════════════════════════════════════════════════
#  ENDPOINT — TELEMETRÍA DESDE ESP32 (HTTP alternativo)
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/telemetry", tags=["ESP32"])
async def post_telemetry(data: TelemetryIn, _=Depends(check_esp32_key)):
    doc = {**data.dict(), "tank_id": 1, "created_at": datetime.utcnow()}
    await db.telemetry.insert_one(doc)
    clean = {k: v for k, v in doc.items() if k != "_id"}
    clean["created_at"] = clean["created_at"].isoformat()
    await ws_manager.broadcast({"type": "telemetry", "data": clean})
    return {"status": "saved"}

@app.post("/api/alert", tags=["ESP32"])
async def post_alert(data: AlertIn, _=Depends(check_esp32_key)):
    doc = {**data.dict(), "tank_id": 1, "created_at": datetime.utcnow()}
    await db.alerts.insert_one(doc)
    clean = {k: v for k, v in doc.items() if k != "_id"}
    clean["created_at"] = clean["created_at"].isoformat()
    await ws_manager.broadcast({"type": "alert", "data": clean})
    return {"status": "saved"}


# ═══════════════════════════════════════════════════════════════════
#  WEBSOCKET — FRONTEND
# ═══════════════════════════════════════════════════════════════════
@app.websocket("/ws")
async def ws_frontend(ws: WebSocket):
    await ws_manager.add_frontend(ws)
    try:
        # Estado inicial
        doc = await db.telemetry.find_one({"tank_id": 1}, {"_id": 0}, sort=[("created_at", -1)])
        if doc and "created_at" in doc:
            doc["created_at"] = doc["created_at"].isoformat()
        await ws.send_text(json.dumps({
            "type": "initial",
            "tank":      doc or {},
            "tank_name": system.tank_name,
            "thresholds": system.thresholds,
            "auto_mode":  system.auto_mode,
            "esp32_online": ws_manager.esp32 is not None,
        }))
        # Mantener vivo con ping/pong
        while True:
            msg = json.loads(await ws.receive_text())
            if msg.get("type") == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.remove_frontend(ws)


# ═══════════════════════════════════════════════════════════════════
#  WEBSOCKET — ESP32
# ═══════════════════════════════════════════════════════════════════
@app.websocket("/ws/device")
async def ws_esp32(ws: WebSocket):
    await ws.accept()
    try:
        # Registro
        raw = await asyncio.wait_for(ws.receive_text(), timeout=10.0)
        msg = json.loads(raw)
        if msg.get("type") != "register" or msg.get("api_key") != API_KEY:
            await ws.close(code=4001); return

        await ws_manager.set_esp32(ws)
        print(f"[ESP32] Conectado")

        # Enviar config actual
        await ws.send_text(json.dumps({
            "type": "command", "action": "set_thresholds",
            "low": system.thresholds["low"], "high": system.thresholds["high"]
        }))
        await ws_manager.broadcast({"type": "esp32_online", "online": True})

        # Loop
        while True:
            raw  = await ws.receive_text()
            msg  = json.loads(raw)

            if msg.get("type") == "telemetry":
                doc = {
                    "tank_id":    1,
                    "level":      float(msg.get("level", 0)),
                    "pump":       bool(msg.get("pump", False)),
                    "valve":      bool(msg.get("valve", False)),
                    "temp":       float(msg.get("temp", 18)),
                    "flow":       float(msg.get("flow", 0)),
                    "pressure":   float(msg.get("pressure", 0)),
                    "created_at": datetime.utcnow(),
                }
                await db.telemetry.insert_one(doc)
                clean = {k: v for k, v in doc.items() if k != "_id"}
                clean["created_at"] = clean["created_at"].isoformat()
                await ws_manager.broadcast({"type": "telemetry", "data": clean})

            elif msg.get("type") == "alert":
                doc = {
                    "tank_id": 1, "alert_type": msg.get("alert_type", ""),
                    "level": float(msg.get("level", 0)), "msg": msg.get("msg", ""),
                    "created_at": datetime.utcnow()
                }
                await db.alerts.insert_one(doc)
                clean = {k: v for k, v in doc.items() if k != "_id"}
                clean["created_at"] = clean["created_at"].isoformat()
                await ws_manager.broadcast({"type": "alert", "data": clean})

    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        ws_manager.clear_esp32()
        print("[ESP32] Desconectado")
        await ws_manager.broadcast({"type": "esp32_online", "online": False})


# ═══════════════════════════════════════════════════════════════════
#  STARTUP
# ═══════════════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup():
    # Cargar umbrales guardados
    cfg = await db.config.find_one({"key": "thresholds"})
    if cfg and "value" in cfg:
        system.thresholds = cfg["value"]

    # Índices
    await db.telemetry.create_index([("tank_id", 1), ("created_at", -1)])
    await db.alerts.create_index([("created_at", -1)])
    await db.action_logs.create_index([("created_at", -1)])
    # TTL: borrar telemetría de más de 30 días
    await db.telemetry.create_index(
        [("created_at", 1)], expireAfterSeconds=2_592_000, name="ttl_30d"
    )
    print("✅ AquaSmart API lista")
