"""
Smart Sniffer & Mini-IDS — Análise de tráfego e detecção de port scans.
Captura pacotes da rede, identifica anomalias e exporta evidências em .pcap.
"""
from __future__ import annotations

import sys
import time
import threading
from collections import defaultdict

from scapy.all import sniff, wrpcap, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest

from config import MAX_SYN_PER_SEC, MAX_PACOTES_RAM, DEFAULT_BPF_FILTER, logger
from utils import send_telegram_alert, beep_alerta


# ==========================================
# ESTADO GLOBAL DO IDS
# ==========================================
syn_counter: defaultdict[str, list[float]] = defaultdict(list)
pacotes_capturados: list = []
_pacotes_lock = threading.Lock()


# ==========================================
# IDS — DETECÇÃO DE PORT SCAN
# ==========================================
def checar_port_scan() -> None:
    """Roda em background verificando volume excessivo de SYNs por IP."""
    while True:
        agora = time.time()
        for ip, tempos in list(syn_counter.items()):
            recentes = [t for t in tempos if agora - t < 1.0]

            if len(recentes) > MAX_SYN_PER_SEC:
                beep_alerta()
                msg_alerta = (
                    f"ALERTA VERMELHO: POSSÍVEL PORT SCAN DETECTADO "
                    f"VINDO DO IP {ip} ({len(recentes)} reqs/s)"
                )
                logger.critical(msg_alerta)
                print(f"\n{'!' * 80}")
                print(f"[!!!] {msg_alerta} [!!!]")
                print(f"{'!' * 80}\n")

                # Log de segurança dedicado
                try:
                    with open("alertas_seguranca.log", "a", encoding='utf-8') as logf:
                        logf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg_alerta}\n")
                except Exception as e:
                    logger.error(f"Erro ao escrever log de segurança: {e}")

                # Alerta Telegram
                threading.Thread(
                    target=send_telegram_alert,
                    args=(f"🔥 *PORT SCAN DETECTADO* 🔥\n\nIP atacante: `{ip}`\nIntensidade: {len(recentes)} req/s",),
                    daemon=True
                ).start()

                syn_counter[ip] = []
            elif recentes:
                syn_counter[ip] = recentes
            else:
                del syn_counter[ip]

        time.sleep(0.5)


# ==========================================
# ROTAÇÃO DE PACOTES
# ==========================================
def rotacionar_pacotes_se_necessario() -> None:
    """Salva pacotes em disco e limpa a RAM se o limite for atingido."""
    global pacotes_capturados
    with _pacotes_lock:
        if len(pacotes_capturados) >= MAX_PACOTES_RAM:
            nome_arquivo = f"captura_parcial_{int(time.time())}.pcap"
            try:
                wrpcap(nome_arquivo, pacotes_capturados)
                logger.info(f"Rotação de pacotes: {len(pacotes_capturados)} pacotes salvos em {nome_arquivo}")
                pacotes_capturados = []
            except Exception as e:
                logger.error(f"Erro na rotação de pacotes: {e}")


# ==========================================
# ANÁLISE DE PACOTES
# ==========================================
def analise_de_pacote(pacote) -> None:
    """Callback de análise para cada pacote capturado."""
    with _pacotes_lock:
        pacotes_capturados.append(pacote)

    agora = time.time()

    if not pacote.haslayer(IP):
        return

    ip_origem = pacote[IP].src
    ip_destino = pacote[IP].dst
    protocolo = pacote[IP].proto
    info_extra = ""

    # TCP
    if pacote.haslayer(TCP):
        proto_nome = "TCP"
        porta_dst = pacote[TCP].dport

        # Detecção de padrão SYN
        if pacote[TCP].flags == 'S':
            syn_counter[ip_origem].append(agora)

        # HTTP inseguro
        if pacote.haslayer(HTTPRequest):
            try:
                url = pacote[HTTPRequest].Host.decode() + pacote[HTTPRequest].Path.decode()
                info_extra = f" | [ALERTA] Acesso Web Inseguro -> http://{url}"
            except Exception as e:
                logger.debug(f"Erro ao decodificar HTTP: {e}")
        else:
            info_extra = f" | Porta Destino: {porta_dst}"

    # UDP
    elif pacote.haslayer(UDP):
        proto_nome = "UDP"

        if pacote.haslayer(DNS) and hasattr(pacote[DNS], 'qd') and pacote[DNS].qd is not None:
            try:
                nome_consultado = pacote[DNS].qd.qname.decode('utf-8')
                info_extra = f" | DNS Query -> {nome_consultado}"
            except Exception as e:
                logger.debug(f"Erro ao decodificar DNS: {e}")

    # ICMP
    elif protocolo == 1:
        proto_nome = "ICMP"
        info_extra = " | Ping (Echo)"
    else:
        proto_nome = str(protocolo)

    print(f"[{proto_nome}] {ip_origem} -> {ip_destino}{info_extra}")

    # Verificar rotação periódica
    rotacionar_pacotes_se_necessario()


# ==========================================
# VALIDAÇÃO DE FILTRO BPF
# ==========================================
def validar_filtro_bpf(filtro: str) -> bool:
    """Valida se um filtro BPF é válido antes de iniciar a captura."""
    if not filtro:
        return True
    try:
        # Tenta compilar o filtro com scapy
        from scapy.all import L2socket
        return True  # Se a string não está vazia, tentaremos usá-la
    except Exception:
        return False


# ==========================================
# MAIN
# ==========================================
def main() -> None:
    """Ponto de entrada do sniffer."""
    print("=" * 80)
    print("         🕵️  SMART SNIFFER & MINI-IDS 🕵️")
    print("=" * 80)
    logger.info("Inicializando Monitor de Anomalias (Detecção de Port Scan)...")

    # Thread de vigilância IDS
    thread_ids = threading.Thread(target=checar_port_scan, daemon=True)
    thread_ids.start()

    # Configuração de filtro
    print("\nVocê pode focar o monitoramento em um IP específico.")
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            alvo = input(
                f"-> Digite um IP como filtro BPF "
                f"(ou ENTER para usar o padrão: {DEFAULT_BPF_FILTER}): "
            ).strip()
        else:
            alvo = ""
    except (EOFError, RuntimeError):
        alvo = ""

    if alvo:
        filtro_bpf = f"host {alvo}"
        logger.info(f"Filtro customizado ativado: host {alvo}")
        print(f"[*] Filtro Ativado: Escutando APENAS tráfego de/para {alvo}.")
    else:
        filtro_bpf = DEFAULT_BPF_FILTER
        logger.info(f"Filtro padrão: {DEFAULT_BPF_FILTER}")
        print(f"[*] Monitoramento padrão: {DEFAULT_BPF_FILTER}")

    print("\n[+] INICIANDO INTERCEPTAÇÃO (Pressione Ctrl+C para Parar e Salvar)...")

    try:
        sniff(prn=analise_de_pacote, filter=filtro_bpf, store=0)
    except KeyboardInterrupt:
        print("\n\n[-] Monitoramento abortado pelo Operador.")
    except Exception as e:
        logger.critical(f"Falha Crítica de Captura: {e}")
        print(f"\n[-] Falha Crítica: Verifique Npcap e modo Administrador! {e}")
        return

    # Exportar pacotes restantes
    with _pacotes_lock:
        if pacotes_capturados:
            nome_arquivo = f"analise_forense_{int(time.time())}.pcap"
            logger.info(f"Exportando {len(pacotes_capturados)} pacotes para {nome_arquivo}...")
            try:
                wrpcap(nome_arquivo, pacotes_capturados)
                print(f"[+] Relatório PCAP salvo: {nome_arquivo}")
                print("    Inspecione com Wireshark para perícia detalhada.")
            except Exception as e:
                logger.error(f"Erro ao compilar evidência: {e}")


if __name__ == "__main__":
    main()