@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo   Windows Native CMake Build
echo ==========================================

set "PROJECT_DIR=%~dp0"
set "BUILD_DIR=%PROJECT_DIR%build_win"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

:: CMake kontrolü
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Hata: 'cmake' komutu bulunamadı. Lütfen CMake'in PATH'e ekli olduğundan emin olun.
    exit /b 1
)

:: CMake derleme konfigürasyonu
cmake -DCMAKE_BUILD_TYPE=Release "%PROJECT_DIR%"
cmake --build . --config Release

if exist "bin\Release\SecureKeyRetriever.exe" (
    echo.
    echo [+] BAŞARILI! Çıktı: %BUILD_DIR%\bin\Release\SecureKeyRetriever.exe
) else if exist "bin\SecureKeyRetriever.exe" (
    echo.
    echo [+] BAŞARILI! Çıktı: %BUILD_DIR%\bin\SecureKeyRetriever.exe
) else (
    echo.
    echo [-] Derleme Başarısız!
)

endlocal
