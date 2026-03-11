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

1.  **Python 3.10+**
2.  **Npcap (Windows)** ou libpcap (Linux) instalados no sistema para permitir o *Packet Sniffing* a nível de hardware.

Clone este repositório e instale as dependências:
```bash
git clone https://github.com/SeuUsuario/network-monitor.git
cd network-monitor
pip install -r requirements.txt
```

## ⚙️ Configuração

1. Faça uma cópia do arquivo de ambiente:
```bash
cp .env.example .env
```
2. Edite o `.env` e configure:
   - **Telegram**: Bot Token e Chat ID para receber alertas.
   - **Redes**: `REDES_ALVO` e `GATEWAYS` com as sub-redes e gateways da sua rede.
   - **SSIDs** (opcional): `REDES_SSIDS` para identificar cada rede pelo nome.
3. (Opcional) Popule o arquivo `dispositivos_conhecidos.json` com os Endereços MAC (formato `AA:BB:CC:DD:EE:FF`) dos aparelhos confiáveis.

### Arquitetura de Módulos
| Arquivo | Descrição |
|---|---|
| `config.py` | Configuração central (redes, logging, constantes) |
| `utils.py` | Funções compartilhadas (Telegram, MAC vendor, etc.) |
| `monitor.py` | Scanner ARP + IPS |
| `sniffer.py` | Sniffer de pacotes + IDS |

## 📖 Tutorial Passo a Passo (Para Iniciantes)

Se você não tem familiaridade com programação, siga estes passos simples para proteger sua rede de casa:

### Passo 1: Preparando o Computador (Windows)
1. **Instale o Python**: Baixe e instale o [Python 3](https://www.python.org/downloads/) oficial. **Importante**: Na primeira tela da instalação, marque a caixinha **"Add Python to PATH"**.
2. **Instale o Npcap**: Baixe e instale o [Npcap](https://npcap.com/#download) (ele é a "placa de rede virtual" que permite que o Python enxergue todos os vizinhos do seu Wi-Fi).
3. **Baixe este projeto**: Clique no botão verde `<> Code` no topo desta página do GitHub e selecione **"Download ZIP"**. Extraia a pasta no seu computador (por exemplo, em `C:\Network-Monitor-Bot`).

### Passo 2: Configurando o Bot do Telegram
Para o script te mandar mensagens no celular quando um intruso entrar:
1. Abra o seu Telegram, pesquise por **@BotFather** e inicie uma conversa.
2. Envie o comando `/newbot` e siga as instruções para criar um nome e um "username" terminando em `bot` (ex: `MeuGuardião_bot`).
3. O BotFather vai te dar um **Token** (código longo). Copie esse número.
4. Pesquise por **@userinfobot**, inicie-o e anote o seu número de **Id** (ex: `103123456`).
5. Volte no Telegram, pesquise o `@nome` do robô que você acabou de criar no passo 2 e clique em **Iniciar**.

### Passo 3: Cadastrando suas Configurações
1. Abra a pasta do projeto que você baixou.
2. Dê um duplo-clique no arquivo `install_requirements.bat` (ou abra o terminal CMD na pasta e digite `pip install -r requirements.txt`). Isso vai baixar o "Scapy".
3. Renomeie o arquivo `.env.example` para apenas `.env`.
4. Abra o `.env` no Bloco de Notas e cole o seu `Token` e o seu `ID` do Telegram que você pegou no Passo 2. Salve e feche.
5. (Opcional): Descubra os endereços "MAC" dos seus celulares/TVs de casa e ensine o robô a ignorá-los adicionando-os no arquivo `dispositivos_conhecidos.json`.

### Passo 4: Iniciando a Vigilância
Você tem duas opções de uso:

**▶️ Opção A: Rodar Manualmente com Fio Vermelho (Tela Preta)**
Apenas abra o Menu Iniciar, procure pelo programa `CMD` (Prompt de Comando), clique com o **Botão Direito -> Executar como Administrador**. 
Vá até a pasta do projeto e digite:
```cmd
python monitor.py
```

**👻 Opção B: O "Modo Fantasma" Automático via Agendador de Tarefas (Recomendado)**
Para que o seu computador vigie o Wi-Fi 24 horas por dia sem janelas abertas:
1. Abra o Menu Iniciar do Windows e digite **Agendador de Tarefas** (*Task Scheduler*).
2. Na aba da direita, clique em **Criar Tarefa...** (Não use a Básica).
3. Na aba **Geral**:
   - Dê o nome de `NetworkMonitor_Background`.
   - Marque a caixinha **"Executar com privilégios mais altos"** (Obrigatório).
   - Marque **"Executar estando o usuário logado ou não"** (Deixa o processo invisível).
4. Na aba **Disparadores**: Clique em Novo, escolha **Ao iniciar o sistema**. Em "Repetir a tarefa a cada:", digite **10 minutos**, com duração "Indefinidamente".
5. Na aba **Ações**: 
   - Clique em Novo. Em Programa/script, digite `pythonw.exe`
   - Em "Adicione argumentos", digite `monitor.py`
   - Em "Iniciar em (Opcional)", **cole o caminho completo da pasta do seu projeto** (ex: `C:\Network-Monitor-Bot\`).
6. Salve a tarefa e digite a senha do seu usuário do Windows. 


---

## ⚠️ Aviso Legal
Estes scripts foram desenvolvidos com intenções **puramente educacionais e de defesa cibernética (Blue Team)**. 
O módulo de 'Cortar Conexão' realiza ativamente um ataque de Man-in-the-Middle (MITM) na rede. **Execute-o EXCLUSIVAMENTE em redes onde você seja o proprietário legal e administrador.** Jamais direcione esta ferramenta contra redes públicas ou sistemas de terceiros.
