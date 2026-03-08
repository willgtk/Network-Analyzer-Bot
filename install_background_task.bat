@echo off
chcp 65001 >nul
echo ==========================================================
echo Instalador do Network Monitor Silencioso (Em Segundo Plano)
echo ==========================================================

:: Verifica se esta rodando como Administrador
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [!] ERRO: Este script PRECISA ser executado como Administrador.
    echo Por favor, feche esta janela, clique com o botao direito em "install_background_task.bat" e escolha "Executar como Administrador".
    pause
    exit /b
)

echo [+] Privilegios de administrador detectados.
set SCRIPT_PATH=%~dp0monitor.py

echo [*] Configurando Agendador de Tarefas do Windows...
:: Usa o pythonw.exe que eh a versao "Hidden" (sem janela) do Python,
:: Executa a cada 10 minutos indefinidamente com maximo privilegio para o Npcap funcionar
schtasks /create /tn "NetworkMonitor_Background" /tr "pythonw.exe \"%SCRIPT_PATH%\"" /sc minute /mo 10 /rl highest /f

if %errorLevel% EQU 0 (
    echo.
    echo [x] Sucesso! O Network Monitor agora esta rodando invisivel.
    echo [x] Ele scaneia a rede de 10 em 10 minutos e avisara no Telegram caso algo seja detectado.
    echo.
) else (
    echo.
    echo [-] Falha ao criar a tarefa. Verifique se o caminho do Python esta correto e se o Windows Defender bloqueou a acao.
    echo.
)

pause
