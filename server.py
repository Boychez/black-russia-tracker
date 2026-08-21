import json
import asyncio
import logging
import socket
import struct
from datetime import datetime, timedelta
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

SERVERS_FILE = "servers.json"
CACHE_TTL = 15  # секунд
ENABLE_UDP_QUERIES = True  # Отключить UDP запросы если хостер их блокирует

app = FastAPI(
    title="Black Russia CRMP Test Servers Tracker",
    description="API для отслеживания онлайна на тестовых (PreProd/ST) серверах Black Russia CRMP",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("br_tracker")

# ============================================================
# Модели
# ============================================================

class ServerConfig(BaseModel):
    logo: str = ""
    color: str = ""
    id: int = 0
    name: str
    ip: str
    port: int
    key: Optional[int] = None
    maxonline: int = 1000
    online: int = 0
    status: str = ""
    x2: bool = False

class PlayerInfo(BaseModel):
    name: str
    score: int

class ServerStatus(BaseModel):
    config: ServerConfig
    online: bool
    players: int
    max_players: int
    hostname: str
    gamemode: str
    language: str
    passworded: bool
    version: str
    player_list: list[PlayerInfo]
    last_seen: Optional[str] = None
    error: Optional[str] = None

class AllServersResponse(BaseModel):
    timestamp: str
    total_online: int
    total_max: int
    servers_online_count: int
    servers_offline_count: int
    servers: list[ServerStatus]

class GameServerResponse(BaseModel):
    id: int
    color: str
    name: str
    max_online: int
    x2: bool
    online: int

# ============================================================
# Кэш
# ============================================================

_cache = {}
_cache_ts = {}

def _load_servers() -> list[dict]:
    with open(SERVERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def _cached(key: str) -> Optional[Any]:
    if key in _cache and datetime.now() - _cache_ts.get(key, datetime.min) < timedelta(seconds=CACHE_TTL):
        return _cache[key]
    return None

def _set_cache(key: str, val: Any):
    _cache[key] = val
    _cache_ts[key] = datetime.now()

# ============================================================
# SA-MP Query Protocol — чистая реализация на UDP
# ============================================================
# Формат пакета:
#   "SAMP" (4 байта) + IP_bytes (4) + port_bytes (2) + opcode (1) + [challenge (4)]
# Opcode 'i' = информация о сервере
# Opcode 'c' = список игроков (требует challenge)
# ============================================================

def _build_query(ip: str, port: int, opcode: bytes, challenge: Optional[int] = None) -> bytes:
    """Собирает UDP пакет для SA-MP query."""
    ip_bytes = socket.inet_aton(ip)
    port_bytes = struct.pack(">H", port)
    packet = b"SAMP" + ip_bytes + port_bytes + opcode
    if challenge is not None:
        packet += struct.pack("<I", challenge)
    return packet

def _parse_info_response(data: bytes) -> dict:
    """
    Парсит ответ на 'i' запрос (серверная информация).
    Формат (после 11-байтного заголовка SAMP+IP+port+opcode):
      - passworded: 1 байт
      - players: 2 байта (little-endian)
      - max_players: 2 байта
      - hostname_len: 4 байта
      - hostname: hostname_len байт
      - gamemode_len: 4 байта
      - gamemode: gamemode_len байт
      - language_len: 4 байта
      - language: language_len байт
    """
    pos = 11  # SAMP(4) + IP(4) + port(2) + opcode(1)
    if len(data) < pos + 5:
        raise ValueError("Слишком короткий ответ от сервера")

    passworded = bool(data[pos])
    pos += 1
    players = struct.unpack("<H", data[pos:pos+2])[0]
    pos += 2
    max_players = struct.unpack("<H", data[pos:pos+2])[0]
    pos += 2

    def read_str():
        nonlocal pos
        if pos + 4 > len(data):
            return ""
        strlen = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        if pos + strlen > len(data):
            return ""
        s = data[pos:pos+strlen].decode("utf-8", errors="replace")
        pos += strlen
        return s

    hostname = read_str()
    gamemode = read_str()
    language = read_str()

    return {
        "passworded": passworded,
        "players": players,
        "max_players": max_players,
        "hostname": hostname,
        "gamemode": gamemode,
        "language": language,
    }

def _parse_players_response(data: bytes) -> list:
    """
    Парсит ответ на 'c' запрос (список игроков).
    Формат (после 11-байтного заголовка):
      - player_count: 2 байта
      - для каждого игрока:
          - player_id: 1 байт
          - name: null-terminated string
          - score: 4 байта (little-endian)
          - ping: 4 байта (little-endian)
    """
    pos = 11
    if len(data) < pos + 2:
        return []

    player_count = struct.unpack("<H", data[pos:pos+2])[0]
    pos += 2

    players = []
    for _ in range(player_count):
        if pos + 1 > len(data):
            break
        # player_id = data[pos]  # не используем
        pos += 1

        # null-terminated string
        name_end = data.find(b"\x00", pos)
        if name_end == -1 or name_end == pos:
            break
        name = data[pos:name_end].decode("utf-8", errors="replace")
        pos = name_end + 1

        if pos + 8 > len(data):
            break
        score = struct.unpack("<I", data[pos:pos+4])[0]
        # ping = struct.unpack("<I", data[pos+4:pos+8])[0]  # не используем
        pos += 8

        players.append({"name": name, "score": score})

    return players

async def _query_udp(ip: str, port: int, opcode: bytes, challenge: Optional[int] = None, timeout: float = 5.0) -> bytes:
    """Отправляет UDP запрос и получает ответ от сервера."""
    loop = asyncio.get_event_loop()

    def _sync():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            packet = _build_query(ip, port, opcode, challenge)
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(4096)
            return data
        except PermissionError as e:
            logger.error(f"Permission denied при запросе к {ip}:{port} - возможно ограничение на сервере")
            raise OSError(f"Permission denied: {e}")
        except Exception as e:
            raise
        finally:
            if sock:
                sock.close()

    return await loop.run_in_executor(None, _sync)

async def query_server(server_cfg: dict) -> ServerStatus:
    """Опрашивает один CRMP сервер и возвращает полный статус."""
    ip = server_cfg["ip"]
    port = server_cfg["port"]
    key = server_cfg.get("key")
    now = datetime.now().isoformat()

    # Если UDP запросы отключены, используем данные из конфига
    if not ENABLE_UDP_QUERIES:
        return ServerStatus(
            config=ServerConfig(**server_cfg),
            online=True,
            players=server_cfg.get("online", 0),
            max_players=server_cfg.get("maxonline", 0),
            hostname="",
            gamemode="",
            language="",
            passworded=False,
            version="",
            player_list=[],
            last_seen=now,
            error=None,
        )

    # Шаг 1: получаем базовую информацию о сервере (без challenge)
    try:
        raw_info = await _query_udp(ip, port, b"i", timeout=10.0)
        info = _parse_info_response(raw_info)
    except socket.timeout:
        return ServerStatus(
            config=ServerConfig(**server_cfg),
            online=False, players=0, max_players=0,
            hostname="", gamemode="", language="",
            passworded=False, version="",
            player_list=[], error="timeout"
        )
    except PermissionError as e:
        logger.error(f"Permission denied для {ip}:{port}")
        return ServerStatus(
            config=ServerConfig(**server_cfg),
            online=False, players=0, max_players=0,
            hostname="", gamemode="", language="",
            passworded=False, version="",
            player_list=[], error=f"permission_denied"
        )
    except ConnectionRefusedError:
        return ServerStatus(
            config=ServerConfig(**server_cfg),
            online=False, players=0, max_players=0,
            hostname="", gamemode="", language="",
            passworded=False, version="",
            player_list=[], error="connection_refused"
        )
    except OSError as e:
        return ServerStatus(
            config=ServerConfig(**server_cfg),
            online=False, players=0, max_players=0,
            hostname="", gamemode="", language="",
            passworded=False, version="",
            player_list=[], error=f"socket_error: {e}"
        )
    except Exception as e:
        return ServerStatus(
            config=ServerConfig(**server_cfg),
            online=False, players=0, max_players=0,
            hostname="", gamemode="", language="",
            passworded=False, version="",
            player_list=[], error=str(e)
        )

    # Шаг 2: получаем список игроков (с challenge key, если указан)
    player_list = []
    try:
        # Пробуем с key если он есть, иначе без challenge
        challenge = key if key is not None else None
        raw_players = await _query_udp(ip, port, b"c", challenge=challenge, timeout=4.0)
        player_list = _parse_players_response(raw_players)
    except socket.timeout:
        # Сервер может не отвечать на запрос игроков — это нормально
        logger.warning(f"timeout при запросе игроков с {ip}:{port}")
    except Exception as e:
        logger.warning(f"ошибка при запросе игроков с {ip}:{port}: {e}")

    # Поле 'version' отсутствует в базовом ответе 'i', но можно получить через 'r' (rules)
    version = "unknown"
    try:
        raw_rules = await _query_udp(ip, port, b"r", challenge=challenge if key else None, timeout=4.0)
        version = _parse_version_from_rules(raw_rules)
    except:
        pass

    return ServerStatus(
        config=ServerConfig(**server_cfg),
        online=True,
        players=info["players"],
        max_players=info["max_players"],
        hostname=info["hostname"],
        gamemode=info["gamemode"],
        language=info["language"],
        passworded=info["passworded"],
        version=version,
        player_list=[PlayerInfo(**p) for p in player_list],
        last_seen=now,
        error=None,
    )

def _parse_version_from_rules(data: bytes) -> str:
    """
    Парсит ответ 'r' (rules), ищет ключ 'version' или 'artime'.
    Формат: после 11-байт заголовка:
      - rules_count: 2 байта
      - для каждого правила:
          - key_len: 1 байт
          - key: key_len байт
          - value_len: 1 байт
          - value: value_len байт
    """
    pos = 11
    if len(data) < pos + 2:
        return "unknown"

    rules_count = struct.unpack("<H", data[pos:pos+2])[0]
    pos += 2

    for _ in range(rules_count):
        if pos + 1 > len(data):
            break
        klen = data[pos]
        pos += 1
        if pos + klen > len(data):
            break
        key = data[pos:pos+klen].decode("utf-8", errors="replace").lower()
        pos += klen

        if pos + 1 > len(data):
            break
        vlen = data[pos]
        pos += 1
        if pos + vlen > len(data):
            break
        value = data[pos:pos+vlen].decode("utf-8", errors="replace")
        pos += vlen

        if key in ("version", "artime", "build"):
            return value

    return "unknown"

# ============================================================
# Endpoints
# ============================================================

@app.get("/", tags=["Status"])
async def root():
    servers = _load_servers()
    return {
        "api": "Black Russia CRMP Test Servers Tracker",
        "version": "1.2.0",
        "servers_count": len(servers),
        "servers": [{"name": s["name"], "ip": s["ip"], "port": s["port"], "id": s.get("id")} for s in servers],
        "endpoints": {
            "/servers": "Статус всех тестовых серверов",
            "/server/{name}": "Статус по имени",
            "/server/id/{id}": "Статус по ID",
            "/total": "Сводка по всем серверам",
        },
    }

@app.get("/servers", response_model=AllServersResponse, tags=["Servers"])
async def get_all_servers(no_cache: bool = Query(False)):
    cache_key = "all_servers"
    if not no_cache:
        cached = _cached(cache_key)
        if cached:
            return cached

    configs = _load_servers()
    tasks = [query_server(s) for s in configs]
    results = await asyncio.gather(*tasks)

    total_online = sum(s.players for s in results if s.online)
    total_max = sum(s.max_players for s in results)
    online_count = sum(1 for s in results if s.online)
    offline_count = sum(1 for s in results if not s.online)

    response = AllServersResponse(
        timestamp=datetime.now().isoformat(),
        total_online=total_online,
        total_max=total_max,
        servers_online_count=online_count,
        servers_offline_count=offline_count,
        servers=results,
    )

    _set_cache(cache_key, response)
    return response

@app.get("/server/{name}", response_model=ServerStatus, tags=["Servers"])
async def get_server_by_name(name: str):
    servers = _load_servers()
    for s in servers:
        if s["name"].lower() == name.lower():
            return await query_server(s)
    names = ", ".join(s["name"] for s in servers)
    raise HTTPException(404, f"Сервер '{name}' не найден. Доступны: {names}")

@app.get("/server/id/{server_id}", response_model=ServerStatus, tags=["Servers"])
async def get_server_by_id(server_id: int):
    servers = _load_servers()
    for s in servers:
        if s.get("id") == server_id:
            return await query_server(s)
    raise HTTPException(404, f"Сервер с ID {server_id} не найден")

@app.get("/total", tags=["Stats"])
async def get_total():
    all_data = await get_all_servers(no_cache=True)
    return {
        "timestamp": all_data.timestamp,
        "total_online": all_data.total_online,
        "total_max": all_data.total_max,
        "servers_online": all_data.servers_online_count,
        "servers_offline": all_data.servers_offline_count,
        "servers_total": len(all_data.servers),
    }

@app.get("/api/gameservers", response_model=list[GameServerResponse], tags=["Servers"])
async def get_gameservers():
    """Получить список игровых серверов в формате для фронтенда с реальным онлайном."""
    servers = _load_servers()
    tasks = [query_server(s) for s in servers]
    results = await asyncio.gather(*tasks)
    
    return [
        GameServerResponse(
            id=server_cfg.get("id", 0),
            color=server_cfg.get("color", ""),
            name=server_cfg.get("name", ""),
            max_online=status.max_players,
            x2=server_cfg.get("x2", False),
            online=status.players,
        )
        for server_cfg, status in zip(servers, results)
    ]

@app.post("/reload", tags=["Admin"])
async def reload_config():
    """Перезагрузить список серверов без перезапуска сервера."""
    try:
        _load_servers()
        _cache.clear()
        _cache_ts.clear()
        return {"status": "ok", "message": "Конфиг перезагружен"}
    except Exception as e:
        raise HTTPException(500, f"Ошибка: {e}")

# ============================================================
# Пуск
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="=127.0.0.1",
        port=8000,
        log_level="info",
    )
