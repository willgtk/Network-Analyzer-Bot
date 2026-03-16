"""
Network Monitor & IPS Defender — Scanner de rede ativo.
Escaneia redes locais via ARP, detecta intrusos, e permite bloqueio por ARP Spoofing.
"""
from __future__ import annotations

import sys
import os
import csv
import time
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp, send

from config import REDES_ALVO, GATEWAYS, REDES_SSIDS, COMMON_PORTS, logger
from utils import (
    send_telegram_alert, beep_alerta, normalizar_mac,
    carregar_dispositivos_conhecidos, get_vendor
)


# ==========================================
# FUNÇÕES DE REDE
# ==========================================
def get_local_ip() -> str:
    """Descobre o IP local da máquina."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


def scan_single_port(ip: str, port: int, results: list[int]) -> None:
    """Verifica uma única porta (para multithreading)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((ip, port))
        if result == 0:
            results.append(port)
        sock.close()
    except Exception:
        pass


def scan_ports(ip: str) -> tuple[str, str]:
    """Verifica portas comuns usando Threads paralelas."""
    open_port_numbers: list[int] = []

    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        for port in COMMON_PORTS:
            executor.submit(scan_single_port, ip, port, open_port_numbers)

    open_port_numbers.sort()

    if not open_port_numbers:
        return "Nenhuma", "Desconhecido"

    ports_str = ", ".join([f"{p} ({COMMON_PORTS[p]})" for p in open_port_numbers])

    # OS Guessing baseado em portas típicas
    os_guess = "Desconhecido"
    win_ports = {135, 139, 445, 3389}
    if win_ports & set(open_port_numbers):
        os_guess = "Windows"
    elif 22 in open_port_numbers and 3389 not in open_port_numbers:
        os_guess = "Linux/Mac/Router"

    return ports_str, os_guess


# ==========================================
# ARP SPOOFING — BLOQUEIO DE INTRUSOS
# ==========================================
def block_device(target_ip: str, gateway_ip: str, target_mac: str) -> None:
    """Ataque contínuo de ARP Spoofing para desabilitar acesso do alvo ao roteador."""
    logger.warning(f"INICIANDO BLOQUEIO CONTRA {target_ip} ({target_mac}).")
    try:
        while True:
            packet_victim = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            send(packet_victim, verbose=False)
            time.sleep(2)
    except Exception as e:
        logger.error(f"Erro na thread de bloqueio: {e}")


# ==========================================
# SCAN ARP
# ==========================================
def scan_arp(redes: list[str]) -> list[tuple]:
    """Executa scan ARP em múltiplas redes e retorna dispositivos encontrados."""
    result = []
    for ip_range in redes:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            res = srp(packet, timeout=3, verbose=0)[0]
            for sent, received in res:
                result.append((received, ip_range))
        except Exception as e:
            logger.error(f"Erro ao capturar pacotes na rede {ip_range}: {e}")
    return result


def enriquecer_dispositivos(
    result: list[tuple],
    dispositivos_conhecidos: dict[str, str],
    my_ip: str
) -> tuple[list[dict], list[dict]]:
    """Enriquece dispositivos com vendor, portas, hostname e classifica como intruso ou confiável."""
    clients: list[dict] = []
    intrusos: list[dict] = []
    mac_to_ip: dict[str, str] = {}

    for received, ip_range in result:
        ip = received.psrc
        mac_raw = received.hwsrc
        mac = normalizar_mac(mac_raw)
        ssid = REDES_SSIDS.get(ip_range, "Desconhecida")

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Desconhecido"

        vendor = get_vendor(mac)
        ports_str, os_guess = scan_ports(ip)

        # Classificação de confiabilidade
        if mac in dispositivos_conhecidos:
            status = dispositivos_conhecidos[mac]
            mac_to_ip[mac] = ip
        elif mac in mac_to_ip and mac_to_ip[mac] != ip:
            status = "ALERTA: MAC CLONADO!"
            intrusos.append({'ip': ip, 'mac': mac, 'hostname': hostname})
        else:
            mac_to_ip[mac] = ip
            if ip not in GATEWAYS and ip != my_ip:
                status = "INTRUSO/NOVO!"
                intrusos.append({'ip': ip, 'mac': mac, 'hostname': hostname})
            else:
                status = "Confiável (Local)"

        clients.append({
            'ip': ip, 'mac': mac, 'ssid': ssid, 'hostname': hostname,
            'os': os_guess, 'status': status, 'vendor': vendor, 'ports': ports_str
        })
        time.sleep(0.3)

    return clients, intrusos


def imprimir_tabela(clients: list[dict]) -> None:
    """Imprime a tabela de dispositivos encontrados."""
    print("\nLista de Dispositivos Conectados:")
    print("-" * 170)
    print("{:<16} | {:<18} | {:<18} | {:<20} | {:<15} | {:<20} | {:<20} | {}".format(
        "IP", "MAC", "Rede (SSID)", "Hostname", "OS Provável", "Status", "Fabricante", "Portas Abertas"))
    print("-" * 170)

    for client in clients:
        vendor_short = (client['vendor'][:18] + '...') if len(client['vendor']) > 18 else client['vendor']
        hostname_short = (client['hostname'][:18] + '...') if len(client['hostname']) > 18 else client['hostname']
        status_str = client['status']
        if "INTRUSO" in status_str or "CLONADO" in status_str:
            status_str = f"!!! {status_str} !!!"

        print("{:<16} | {:<18} | {:<18} | {:<20} | {:<15} | {:<20} | {:<20} | {}".format(
            client['ip'], client['mac'], client['ssid'], hostname_short, client['os'],
            status_str, vendor_short, client['ports']))


def exportar_csv(clients: list[dict]) -> str:
    """Exporta os dados para CSV com timestamp no nome."""
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    csv_file = f"relatorio_rede_{timestamp}.csv"
    try:
        with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=['ip', 'mac', 'ssid', 'hostname', 'os', 'status', 'vendor', 'ports'])
            writer.writeheader()
            writer.writerows(clients)
        logger.info(f"Relatório exportado: {os.path.abspath(csv_file)}")
        print(f"\n[+] Relatório exportado com sucesso para {os.path.abspath(csv_file)}")
    except Exception as e:
        logger.error(f"Erro ao salvar relatório CSV: {e}")
    return csv_file


def tratar_intrusos(intrusos: list[dict]) -> None:
    """Alerta, notifica via Telegram, e oferece bloqueio ARP para intrusos detectados."""
    if not intrusos:
        print("\n[+] Nenhum intruso detectado. Rede segura.")
        logger.info("Varredura concluída. Nenhum intruso detectado.")
        return

    beep_alerta()
    beep_alerta()

    print("\n" + "!" * 60)
    print(f"ALERTA VERMELHO: Foram detectados {len(intrusos)} dispositivos desconhecidos no seu WiFi!")
    print("!" * 60)

    # Monta a mensagem para o Telegram
    msg_telegram = f"🚨 *ALERTA DE REDE* 🚨\nForam detectados {len(intrusos)} dispositivo(s) não autorizado(s):\n\n"

    for intruso in intrusos:
        print(f" -> IP: {intruso['ip']} | MAC: {intruso['mac']} | Nome: {intruso['hostname']}")
        msg_telegram += f"📡 IP: `{intruso['ip']}`\n"
        msg_telegram += f"🏷️ MAC: `{intruso['mac']}`\n"
        msg_telegram += f"💻 Nome: {intruso['hostname']}\n\n"

    threading.Thread(target=send_telegram_alert, args=(msg_telegram,), daemon=True).start()

    # Oferecer bloqueio
    for intruso in intrusos:
        try:
            if sys.stdin is None or not sys.stdin.isatty():
                logger.info("Modo background detectado. Bloqueio automático ignorado.")
                resp = 'n'
            else:
                resp = input(f"\nDeseja DESTRUIR A CONEXÃO deste dispositivo? ({intruso['ip']})? (s/N): ")
        except (EOFError, RuntimeError):
            resp = 'n'

        if resp.lower().strip() == 's':
            # Encontra o gateway correto para a sub-rede do intruso
            alvo_gateway = GATEWAYS[0]  # Fallback
            for gw in GATEWAYS:
                prefix = '.'.join(gw.split('.')[:3])
                if intruso['ip'].startswith(prefix + '.'):
                    alvo_gateway = gw
                    break

            t = threading.Thread(target=block_device, args=(intruso['ip'], alvo_gateway, intruso['mac']))
            t.daemon = True
            t.start()
            logger.warning(f"Escudo Ativado: ARP Spoofing contra {intruso['ip']}")
            print(f"[*] Escudo Ativado: Envenenando ARP contra {intruso['ip']}.")

    # Manter vivo se houver threads de bloqueio
    try:
        threads_ativas = [t for t in threading.enumerate() if t != threading.main_thread()]
        if threads_ativas:
            print("\n[!] Bloqueio(s) Ativo(s)... Deixe esta janela aberta. Ctrl+C para encerrar.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Aplicação encerrada. O invasor recuperará o acesso em instantes.")


# ==========================================
# FUNÇÃO PRINCIPAL
# ==========================================
def scan_network() -> tuple[list[dict], list[dict]]:
    """Executa a varredura completa de rede."""
    my_ip = get_local_ip()

    print("=" * 60)
    print("        🛡️ NETWORK MONITOR & IPS DEFENDER 🛡️")
    print("=" * 60)
    print(f"Seu IP = {my_ip}, Gateways = {', '.join(GATEWAYS)}")
    print(f"Escaneando as redes: {', '.join(REDES_ALVO)}...\n")

    # 1. Scan ARP
    result = scan_arp(REDES_ALVO)
    dispositivos_conhecidos = carregar_dispositivos_conhecidos()

    print(f"Encontrados {len(result)} dispositivos ativos. Coletando informações (OS, Portas)...")

    # 2. Enriquecer dados
    clients, intrusos = enriquecer_dispositivos(result, dispositivos_conhecidos, my_ip)

    # 3. Exibir e exportar
    imprimir_tabela(clients)
    exportar_csv(clients)

    # 4. Tratar intrusos
    tratar_intrusos(intrusos)

    return clients, intrusos


if __name__ == "__main__":
    try:
        clients, intrusos = scan_network()

        msg = (
            f"🔄 *Varredura Concluída*\n\n"
            f"✅ Status: *Sucesso*\n"
            f"📱 Total Dispositivos: {len(clients)}\n"
            f"🛡️ Intrusos Encontrados: {len(intrusos)}\n\n"
            f"📋 *Dispositivos Conectados:*\n"
        )
        for c in clients:
            status_emoji = "🔴" if "INTRUSO" in c['status'] or "CLONADO" in c['status'] else "🟢"
            nome_exibicao = c['status'] if status_emoji == "🟢" and c['status'] != "Confiável (Local)" else c['hostname']
            msg += f"{status_emoji} `{c['ip']}` - {nome_exibicao} ({c['mac']})\n"
        threading.Thread(target=send_telegram_alert, args=(msg,), daemon=True).start()
        # Aguardar thread do Telegram finalizar
        time.sleep(2)

    except Exception as e:
        logger.critical(f"Erro Crítico: {e}")
        erro_msg = f"❌ *FALHA NA VARREDURA*\n\nErro crítico no Network Monitor:\n`{str(e)}`"
        send_telegram_alert(erro_msg)