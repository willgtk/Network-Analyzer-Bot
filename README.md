# Network Monitor & IPS Defender 🛡️

Um conjunto de scripts Python avançados para monitoramento ativo de redes Wi-Fi, detecção de intrusos e interdição de ataques (Port Scans / MAC Spoofing) com alertas integrados via Telegram.

## 🚀 Funcionalidades

### 1. Monitor de Rede Ativo (`monitor.py`)
Escaneia ativamente as redes locais para mapear os dispositivos conectados.
*   **Varredura Multirrede**: Suporte para varredura simultânea em múltiplas sub-redes reais ou virtuais (ex: Redes IoT / Redes Guests isoladas).
*   **Identificação de Intrusos**: Mantém uma lista de segurança (`dispositivos_conhecidos.json`). Qualquer aparelho não cadastrado aciona um alerta visual e sonoro imediato.
*   **Detecção de MAC Spoofing**: Identifica se um mesmo endereço físico (MAC Address) está operando sob múltiplos IPs de forma anômala na rede, ignorando sabiamente dispositivos de ponte conhecidos.
*   **Ataque IPS (Block Device)**: Em caso de intrusão detectada, permite ao administrador cortar o acesso à internet do invasor em tempo real sob demanda, disparando um ataque de [ARP Spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) diretamente contra a vítima e o gateway.
*   **Exportação de Evidências**: Gera um relatório automático `relatorio_rede.csv` a cada varredura contendo IP, MAC, Fabricante e Portas Abertas do invasor.

### 2. Smart Sniffer & Mini-IDS (`sniffer.py`)
Analisa silenciosamente o tráfego da rede para encontrar anomalias comportamentais e port scans.
*   **Intrusion Detection System (IDS)**: Analisa volumes de requisições `SYN` puros. Ao detectar uma taxa superior a 20 requisições TCP por segundo vindas do mesmo IP, emite um alerta vermelho de "Port Scan" bloqueável.
*   **Filtro BPF Hardened**: Coleta eficiente de rede direto da placa de rede.
*   **Análise Forense (PCAP)**: Exporta um fragmento limpo do ataque em `.pcap` ao ser finalizado, perfeitamente auditável usando o Wireshark.

### 3. Integração com Telegram 📱
Para que você não precise ficar olhando o terminal o tempo inteiro, os scripts se comunicam via API com um Bot do Telegram.
Sempre que um Dispositivo Novo conectar (Monitor) ou um Port Scan acontecer (Sniffer), você receberá uma notificação formatada no seu Telegram imediatamente.

---

## 🛠️ Requisitos e Instalação

1.  **Python 3.8+**
2.  **Npcap (Windows)** ou libpcap (Linux) instalados no sistema para permitir o *Packet Sniffing* a nível de hardware.

Clone este repositório e instale as dependências:
```bash
git clone https://github.com/SeuUsuario/network-monitor.git
cd network-monitor
pip install -r requirements.txt
```

*(Nota: Crie um `requirements.txt` contendo as libs `scapy`, `python-dotenv`.)*

## ⚙️ Configuração

1. Faça uma cópia do arquivo de ambiente:
```bash
cp .env.example .env
```
2. Edite o `.env` gerado e inclua suas credenciais do Telegram (Bot Token e Chat ID).
3. (Opcional) Popule o arquivo `dispositivos_conhecidos.json` com os Endereços MAC em **MAIÚSCULAS** dos aparelhos da sua casa que são de confiança.

## 🏃 Como usar

Esses scripts manipulam a placa de rede e enviam pacotes cruciais, logo **eles requerem execução em Modo Administrador (Windows) ou `sudo` (Linux)**.

Iniciando o Monitoramento Geral:
```bash
python monitor.py
```

Iniciando o IDS Passivo:
```bash
python sniffer.py
```

## ⚠️ Aviso Legal
Estes scripts foram desenvolvidos com intenções **puramente educacionais e de defesa cibernética (Blue Team)**. 
O módulo de 'Cortar Conexão' realiza ativamente um ataque de Man-in-the-Middle (MITM) na rede. **Execute-o EXCLUSIVAMENTE em redes onde você seja o proprietário legal e administrador.** Jamais direcione esta ferramenta contra redes públicas ou sistemas de terceiros.
