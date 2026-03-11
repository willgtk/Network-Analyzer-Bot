"""
Utilitários compartilhados do Network Monitor.
Funções de notificação Telegram, alerta sonoro e manipulação de MAC.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.parse

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, logger

# Cache local de MAC → Vendor (evita chamadas HTTP repetidas)
_VENDOR_CACHE_PATH: str = os.path.join(os.path.dirname(__file__), 'vendor_cache.json')
_vendor_cache: dict[str, str] = {}


def _carregar_vendor_cache() -> None:
    """Carrega o cache de vendors do disco."""
    global _vendor_cache
    if os.path.exists(_VENDOR_CACHE_PATH):
        try:
            with open(_VENDOR_CACHE_PATH, 'r', encoding='utf-8') as f:
                _vendor_cache = json.load(f)
        except Exception:
            _vendor_cache = {}


def _salvar_vendor_cache() -> None:
    """Persiste o cache de vendors no disco."""
    try:
        with open(_VENDOR_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(_vendor_cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.debug(f"Erro ao salvar cache de vendors: {e}")


# Carrega o cache na inicialização
_carregar_vendor_cache()


def send_telegram_alert(mensagem: str) -> None:
    """Envia uma mensagem de alerta via Telegram Bot."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Credenciais do Telegram não configuradas no .env")
        return

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({
            'chat_id': TELEGRAM_CHAT_ID,
            'text': mensagem,
            'parse_mode': 'Markdown'
        }).encode('utf-8')
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.error(f"Erro ao enviar alerta no Telegram: {e}")


def beep_alerta() -> None:
    """Emite alerta sonoro (Windows) ou log (outros SO)."""
    try:
        import winsound
        winsound.Beep(1000, 500)
    except (ImportError, RuntimeError):
        logger.info("🔔 ALERTA SONORO (winsound indisponível neste SO)")


def normalizar_mac(mac: str) -> str:
    """Normaliza um MAC address para MAIÚSCULAS com separador ':'."""
    return mac.upper().replace('-', ':')


def carregar_dispositivos_conhecidos(caminho: str = 'dispositivos_conhecidos.json') -> dict[str, str]:
    """Carrega a allowlist de dispositivos com MACs normalizados."""
    if os.path.exists(caminho):
        try:
            with open(caminho, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Normaliza chaves: MAIÚSCULAS + separador ':'
                return {normalizar_mac(k): v for k, v in data.items()}
        except json.JSONDecodeError as e:
            logger.error(f"Erro ao ler {caminho}: {e}")
        except Exception as e:
            logger.error(f"Erro inesperado ao carregar dispositivos: {e}")
    else:
        logger.info(f"Sugestão: Crie/edite '{caminho}' para cadastrar seus aparelhos!")
    return {}


def get_vendor(mac_address: str) -> str:
    """Obtém o fabricante do dispositivo via OUI prefix (com cache local)."""
    # Usa os primeiros 8 caracteres (OUI) como chave de cache
    oui = normalizar_mac(mac_address)[:8]
    if oui in _vendor_cache:
        return _vendor_cache[oui]

    vendor = _consultar_vendor_api(mac_address)
    _vendor_cache[oui] = vendor
    _salvar_vendor_cache()
    return vendor


def _consultar_vendor_api(mac_address: str) -> str:
    """Consulta APIs externas para resolver MAC → Fabricante."""
    # API primária
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode('utf-8')
    except Exception:
        pass

    # API de fallback
    try:
        url = f"https://macvendors.co/api/{mac_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode('utf-8'))
            if 'result' in data and 'company' in data['result']:
                return data['result']['company']
    except Exception:
        pass

    return "Desconhecido"
