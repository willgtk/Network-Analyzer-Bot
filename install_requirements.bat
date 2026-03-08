@echo off
echo ==============================================
echo Instalando Dependencias do Network Monitor...
echo ==============================================
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo [x] Instalacao concluida com sucesso!
pause
