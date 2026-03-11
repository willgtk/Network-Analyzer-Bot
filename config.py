"""
Módulo de configuração central do Network Monitor.
Carrega variáveis de ambiente e define constantes de rede.
"""
from __future__ import annotations

import os
import logging
from dotenv import load_dotenv

load_dotenv()

# ==========================================
# LOGGING
# ==========================================
_log_level_str: str = os.getenv('LOG_LEVEL', 'INFO').upper()
_log_level: int = getattr(logging, _log_level_str, logging.INFO)

logging.basicConfig(
    level=_log_level,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network_monitor.log', encoding='utf-8'),
    ]
)
logger: logging.Logger = logging.getLogger('NetworkMonitor')

# ==========================================
# TELEGRAM
# ==========================================
TELEGRAM_BOT_TOKEN: str | None = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID: str | None = os.getenv('TELEGRAM_CHAT_ID')

# ==========================================
# REDE — Configuração via .env
# ==========================================
_redes_raw: str = os.getenv('REDES_ALVO', '192.168.1.1/24')
REDES_ALVO: list[str] = [r.strip() for r in _redes_raw.split(',') if r.strip()]

_gateways_raw: str = os.getenv('GATEWAYS', '192.168.1.1')
GATEWAYS: list[str] = [g.strip() for g in _gateways_raw.split(',') if g.strip()]

# SSIDs: formato "rede1=SSID1,rede2=SSID2"
_ssids_raw: str = os.getenv('REDES_SSIDS', '')
REDES_SSIDS: dict[str, str] = {}
for entry in _ssids_raw.split(','):
    if '=' in entry:
        rede, ssid = entry.strip().split('=', 1)
        REDES_SSIDS[rede.strip()] = ssid.strip()
# Fallback: se não configurou SSIDs, usa "Desconhecida" para cada rede
for rede in REDES_ALVO:
    if rede not in REDES_SSIDS:
        REDES_SSIDS[rede] = 'Desconhecida'

# Filtro BPF padrão para o sniffer (derivado das redes)
_bpf_parts: list[str] = []
for rede in REDES_ALVO:
    # Transforma "192.168.6.1/24" em "net 192.168.6.0/24"
    base = rede.rsplit('.', 1)[0] + '.0/' + rede.rsplit('/', 1)[-1]
    _bpf_parts.append(f'net {base}')
DEFAULT_BPF_FILTER: str = ' or '.join(_bpf_parts) if _bpf_parts else ''

# ==========================================
# IDS — Configuração do Sniffer
# ==========================================
MAX_SYN_PER_SEC: int = int(os.getenv('MAX_SYN_PER_SEC', '20'))
MAX_PACOTES_RAM: int = int(os.getenv('MAX_PACOTES_RAM', '50000'))

# ==========================================
# PORTAS COMUNS PARA SCAN
# ==========================================
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}
