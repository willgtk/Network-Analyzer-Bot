from scapy.all import sniff, wrpcap, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
import time
import urllib.request
import urllib.parse
from collections import defaultdict
import threading
import os
from dotenv import load_dotenv

load_dotenv()

try:
    import winsound
except ImportError:
    pass

# Configurações do IDS
MAX_SYN_PER_SEC = 20 # Limite de requisições SYN para considerar Port Scan
syn_counter = defaultdict(list)

# Armazenamento de pacotes para o arquivo .pcap
pacotes_capturados = []

def send_telegram_alert(mensagem):
    """Envia uma mensagem de alerta via Telegram Bot."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if not token or not chat_id:
        return
        
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({'chat_id': chat_id, 'text': mensagem}).encode('utf-8')
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass

def checar_port_scan():
    """Roda em background e limpa antigas conexões, verificando excessos de SYN para sinalizar um port scan."""
    while True:
        agora = time.time()
        for ip, tempos in list(syn_counter.items()):
            # Mantém apenas os SYNs (pedidos de conexão nova) do último segundo
            recentes = [t for t in tempos if agora - t < 1.0]
            if len(recentes) > MAX_SYN_PER_SEC:
                try:
                    winsound.Beep(1000, 500)
                except Exception:
                    pass
                msg_alerta = f"[!!!] ALERTA VERMELHO: POSSÍVEL PORT SCAN DETECTADO VINDO DO IP {ip} ({len(recentes)} reqs/s) [!!!]"
                print(f"\n" + "!"*80)
                print(msg_alerta)
                print("!"*80 + "\n")
                
                # Registra no log de segurança
                try:
                    with open("alertas_seguranca.log", "a") as logf:
                        logf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg_alerta}\n")
                except Exception:
                    pass
                
                # Dispara alerta pro Telegram
                threading.Thread(target=send_telegram_alert, args=(f"🔥 *PORT SCAN DETECTADO* 🔥\n\nAtaque vindo de IP: `{ip}`\nIntensidade: {len(recentes)} requisições por segundo.",)).start()
                
                # Zera para não flodar a tela sem parar
                syn_counter[ip] = []
            else:
                if recentes:
                    syn_counter[ip] = recentes
                else:
                    del syn_counter[ip]
        time.sleep(0.5)

def analise_de_pacote(pacote):
    global pacotes_capturados
    pacotes_capturados.append(pacote)
    agora = time.time()

    # Verifica se o pacote tem a camada de IP
    if pacote.haslayer(IP):
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        protocolo = pacote[IP].proto
        
        info_extra = ""
        
        # Analisando TCP
        if pacote.haslayer(TCP):
            proto_nome = "TCP"
            porta_dst = pacote[TCP].dport
            
            # Detecção de Padrão SYN (Início de conexão sem confirmação)
            if pacote[TCP].flags == 'S':
                syn_counter[ip_origem].append(agora)
            
            # Análise de HTTP Puro e envio de Formulários Web (Porta 80)
            if pacote.haslayer(HTTPRequest):
                try:
                    url = pacote[HTTPRequest].Host.decode() + pacote[HTTPRequest].Path.decode()
                    info_extra = f" | [ALERTA] Acesso Web Inseguro -> http://{url}"
                except:
                    pass
            else:
                 info_extra = f" | Porta Destino: {porta_dst}"

        # Analisando UDP
        elif pacote.haslayer(UDP):
            proto_nome = "UDP"
            
            # Análise de DNS (Resoluções de Nomes / Sites sendo acessados pelo usuário)
            # Muito útil para descobrir para quais servidores uma SmartTV está "ligando escondido"
            if pacote.haslayer(DNS) and hasattr(pacote[DNS], 'qd') and pacote[DNS].qd is not None:
                try:
                    nome_consultado = pacote[DNS].qd.qname.decode('utf-8')
                    info_extra = f" | DNS Query (Tentando resolver site) -> {nome_consultado}"
                except:
                    pass
        
        # Analisando ICMP (Ping / Rastreamento)
        elif protocolo == 1:
            proto_nome = "ICMP"
            info_extra = " | Ping (Echo)"
        else:
            proto_nome = str(protocolo)

        print(f"[{proto_nome}] {ip_origem} -> {ip_destino}{info_extra}")

def main():
    print("="*80)
    print("         🕵️  SMART SNIFFER E MINI-IDS (SISTEMA DE DETECÇÃO DE INTRUSOS) 🕵️")
    print("="*80)
    print("[+] Inicializando Monitor de Anomalias de Rede (Detecção de Scan Port)...")
    
    # Inicia a thread que vigia port scans pelo volume de padrões "SYN"
    thread_ids = threading.Thread(target=checar_port_scan)
    thread_ids.daemon = True
    thread_ids.start()
    
    # Parâmetros customizáveis do Sniffer
    print("\nVocê pode focar o monitoramento em um IP específico.")
    alvo = input("-> Digite um IP como filtro BPF (ou apenas aperte ENTER para capturar as redes 192.168.6.0/24 e 192.168.5.0/24): ").strip()
    
    # BPF (Berkeley Packet Filter) -> O filtro é validado DENTRO da placa de rede, garantindo ZERO consumo inútil de CPU
    filtro_bpf = ""
    if alvo:
        filtro_bpf = f"host {alvo}"
        print(f"[*] Filtro Ativado na Placa Mestra: Escutando APENAS tráfego de/para {alvo}.")
    else:
        filtro_bpf = "net 192.168.6.0/24 or net 192.168.5.0/24"
        print("[*] Monitoramento focado nas redes 192.168.6.0/24 e 192.168.5.0/24.")
        
    print("\n[+] INICIANDO INTERCEPTAÇÃO (Pressione Ctrl+C quando quiser Parar e Salvar o Log)...")
    try:
         # Capturamos sempre limitando os logs na RAM por segurança
         sniff(prn=analise_de_pacote, filter=filtro_bpf, store=0)
    except KeyboardInterrupt:
        print("\n\n[-] Monitoramento abortado ativamente pelo Operador.")
    except Exception as e:
        print(f"\n[-] Falha Crítica de Captura: Verifique o Npcap instalado e se abriu em modo Administrador! {e}")
        return

    # O Script terminou (usuário apertou Ctrl+C). Vamos exportar tudo analisado.
    if pacotes_capturados:
        nome_arquivo = f"analise_forense_{int(time.time())}.pcap"
        print(f"[*] Exportando {len(pacotes_capturados)} fragmentos na evidência de arquivo {nome_arquivo}...")
        try:
             wrpcap(nome_arquivo, pacotes_capturados)
             print(f"[+] O Relatório Profissional PCAP foi salvo com sucesso.")
             print("    Você pode inspecionar isso com o software 'Wireshark' mais tarde para perícia detalhada.")
        except Exception as e:
             print(f"[-] Erro ao compilar a evidência: {e}")

if __name__ == "__main__":
    main()