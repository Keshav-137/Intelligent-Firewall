# GUI/firewall_gui.py
# 🔥 Intelligent Firewall — PyQt6 Dashboard
# Beautiful dark cyber-themed GUI with full menu, real-time logs, settings, policy editor

import sys
import os
import json
import time
from datetime import datetime
from collections import deque

# ─── Path setup ───────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for folder in ["Stage1_PacketCapture", "Stage2_RuleEngine",
               "Stage3_4_NGFW_ML", "Stage5_EDR", "Stage6_ZeroTrust", "Core"]:
    p = os.path.join(ROOT, folder)
    if p not in sys.path:
        sys.path.insert(0, p)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
    QTextEdit, QLineEdit, QComboBox, QCheckBox, QGroupBox, QScrollArea,
    QDialog, QDialogButtonBox, QSpinBox, QSplitter, QFrame, QHeaderView,
    QMessageBox, QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QSizePolicy, QStackedWidget, QMenuBar, QMenu, QStatusBar, QToolBar,
    QInputDialog # <-- Important!
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSize, QPropertyAnimation,
    QEasingCurve, QRect, QUrl
)
from PyQt6.QtGui import (
    QColor, QPalette, QFont, QIcon, QPixmap, QPainter, QBrush,
    QLinearGradient, QPen, QAction, QFontDatabase, QDesktopServices
)

# ─── Colour Palette ───────────────────────────────────────────────────────────
C = {
    "bg":        "#0a0e1a",
    "panel":     "#111827",
    "card":      "#1a2235",
    "border":    "#1e3a5f",
    "accent":    "#00d4ff",
    "accent2":   "#7c3aed",
    "green":     "#10b981",
    "red":       "#ef4444",
    "orange":    "#f97316",
    "yellow":    "#fbbf24",
    "text":      "#e2e8f0",
    "text_dim":  "#64748b",
    "header":    "#0f172a",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {C["bg"]};
    color: {C["text"]};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}}
QMenuBar {{
    background-color: {C["header"]};
    color: {C["text"]};
    border-bottom: 1px solid {C["border"]};
    padding: 2px;
}}
QMenuBar::item:selected {{
    background-color: {C["card"]};
    color: {C["accent"]};
}}
QMenu {{
    background-color: {C["panel"]};
    border: 1px solid {C["border"]};
    color: {C["text"]};
}}
QMenu::item:selected {{
    background-color: {C["card"]};
    color: {C["accent"]};
}}
QTabWidget::pane {{
    border: 1px solid {C["border"]};
    background-color: {C["panel"]};
}}
QTabBar::tab {{
    background-color: {C["header"]};
    color: {C["text_dim"]};
    padding: 8px 20px;
    border: 1px solid {C["border"]};
    border-bottom: none;
    margin-right: 2px;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QTabBar::tab:selected {{
    background-color: {C["card"]};
    color: {C["accent"]};
    border-top: 2px solid {C["accent"]};
}}
QTabBar::tab:hover {{
    background-color: {C["card"]};
    color: {C["text"]};
}}
QPushButton {{
    background-color: {C["card"]};
    color: {C["accent"]};
    border: 1px solid {C["accent"]};
    padding: 8px 18px;
    border-radius: 4px;
    font-size: 11px;
    letter-spacing: 1px;
    font-weight: bold;
}}
QPushButton:hover {{
    background-color: {C["accent"]};
    color: {C["bg"]};
}}
QPushButton:pressed {{
    background-color: {C["accent2"]};
    border-color: {C["accent2"]};
    color: white;
}}
QPushButton#danger {{
    color: {C["red"]};
    border-color: {C["red"]};
}}
QPushButton#danger:hover {{
    background-color: {C["red"]};
    color: white;
}}
QPushButton#success {{
    color: {C["green"]};
    border-color: {C["green"]};
}}
QPushButton#success:hover {{
    background-color: {C["green"]};
    color: white;
}}
QPushButton#start_btn {{
    background-color: {C["green"]};
    color: {C["bg"]};
    border-color: {C["green"]};
    padding: 12px 30px;
    font-size: 13px;
    font-weight: bold;
}}
QPushButton#start_btn:hover {{
    background-color: #0f9b6e;
}}
QPushButton#stop_btn {{
    background-color: {C["red"]};
    color: white;
    border-color: {C["red"]};
    padding: 12px 30px;
    font-size: 13px;
    font-weight: bold;
}}
QPushButton#stop_btn:hover {{
    background-color: #c91c1c;
}}
QTableWidget {{
    background-color: {C["panel"]};
    alternate-background-color: {C["card"]};
    gridline-color: {C["border"]};
    border: 1px solid {C["border"]};
    selection-background-color: {C["accent2"]};
    color: {C["text"]};
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}
QHeaderView::section {{
    background-color: {C["header"]};
    color: {C["accent"]};
    border: 1px solid {C["border"]};
    padding: 6px 8px;
    font-weight: bold;
    letter-spacing: 1px;
    font-size: 10px;
    text-transform: uppercase;
}}
QTextEdit {{
    background-color: {C["header"]};
    color: {C["green"]};
    border: 1px solid {C["border"]};
    font-family: 'Consolas', monospace;
    font-size: 11px;
    padding: 8px;
}}
QLineEdit, QSpinBox, QComboBox {{
    background-color: {C["card"]};
    color: {C["text"]};
    border: 1px solid {C["border"]};
    padding: 6px 10px;
    border-radius: 3px;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border-color: {C["accent"]};
}}
QComboBox::drop-down {{
    border: none;
    background: {C["card"]};
}}
QComboBox::down-arrow {{
    color: {C["accent"]};
}}
QComboBox QAbstractItemView {{
    background-color: {C["panel"]};
    color: {C["text"]};
    border: 1px solid {C["border"]};
    selection-background-color: {C["accent2"]};
}}
QGroupBox {{
    border: 1px solid {C["border"]};
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 12px;
    color: {C["accent"]};
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: {C["accent"]};
}}
QCheckBox {{
    color: {C["text"]};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {C["border"]};
    background: {C["card"]};
    border-radius: 2px;
}}
QCheckBox::indicator:checked {{
    background: {C["accent"]};
    border-color: {C["accent"]};
}}
QScrollBar:vertical {{
    background: {C["header"]};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {C["border"]};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {C["accent"]};
}}
QStatusBar {{
    background-color: {C["header"]};
    color: {C["text_dim"]};
    border-top: 1px solid {C["border"]};
    font-size: 10px;
}}
QListWidget {{
    background-color: {C["panel"]};
    border: 1px solid {C["border"]};
    color: {C["text"]};
}}
QListWidget::item:selected {{
    background-color: {C["accent2"]};
}}
QSplitter::handle {{
    background-color: {C["border"]};
}}
"""


# ─── Event Worker Thread ───────────────────────────────────────────────────────
class FirewallWorker(QThread):
    event_received = pyqtSignal(dict)
    status_changed = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._running = False

    def run(self):
        self._running = True
        try:
            from event_bus import subscribe, unsubscribe
            from orchestrator import start_all, get_status

            def on_event(evt):
                if self._running:
                    self.event_received.emit(evt)

            subscribe(on_event)
            start_all()

            # Responsive wait loop ensuring clean unhook upon quick-closes 
            while self._running:
                self.status_changed.emit(get_status())
                for _ in range(10): # Blocks effectively loop length strictly inside Python non-intrusively 
                    if not self._running: break
                    time.sleep(0.2) 

            unsubscribe(on_event)
        except Exception as e:
            self.event_received.emit({
                "stage": "SYSTEM", "action": "ERROR",
                "reason": f"Worker module warning: {e}"
            })
            
            # Simple degraded run-loop permitting test visuals mock operations to show gracefully  
            while self._running:
                self.status_changed.emit({k: False for k in ["Stage1", "Stage2", "Stage3_4", "Stage5", "Stage6"]})
                for _ in range(10): 
                    if not self._running: break
                    time.sleep(0.2) 

    def stop(self):
        self._running = False
        try:
            from orchestrator import stop_all
            stop_all()
        except Exception:
            pass


# ─── Stat Card Widget ──────────────────────────────────────────────────────────
class StatCard(QFrame):
    def __init__(self, title, value="0", color=None, parent=None):
        super().__init__(parent)
        color = color or C["accent"]
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {C["card"]};
                border: 1px solid {C["border"]};
                border-top: 3px solid {color};
                border-radius: 4px;
                padding: 4px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(12, 10, 12, 10)

        self.title_lbl = QLabel(title.upper())
        self.title_lbl.setStyleSheet(f"color: {C['text_dim']}; font-size: 9px; letter-spacing: 2px; font-weight: bold; border: none; background: transparent;")

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold; font-family: 'Consolas'; border: none; background: transparent;")

        layout.addWidget(self.title_lbl)
        layout.addWidget(self.value_lbl)

    def set_value(self, v):
        self.value_lbl.setText(str(v))


# ─── Live Log Table ────────────────────────────────────────────────────────────
class LiveLogTable(QTableWidget):
    MAX_ROWS = 500

    COLS = ["TIME", "STAGE", "ACTION", "SRC IP", "DST IP", "PORT", "PROTOCOL", "REASON"]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS), parent)
        self.setHorizontalHeaderLabels(self.COLS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)
        self._auto_scroll = True

    def add_event(self, event: dict):
        if self.rowCount() >= self.MAX_ROWS:
            self.removeRow(0)

        row = self.rowCount()
        self.insertRow(row)

        action = event.get("action", "")
        color = self._action_color(action)

        values = [
            str(event.get("timestamp", "")),
            str(event.get("stage", "")),
            action,
            str(event.get("src_ip", "")),
            str(event.get("dst_ip", "")),
            str(event.get("port", "")),
            str(event.get("protocol", "")),
            str(event.get("reason", ""))[:60], # Prevents parsing 'none' bugs  
        ]
        
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setForeground(QColor(color))
            self.setItem(row, col, item)

        if self._auto_scroll:
            self.scrollToBottom()

    def _action_color(self, action):
        return {
            "BLOCK":  C["red"],
            "FLOOD":  C["orange"],
            "ATTACK": C["red"],
            "ERROR":  C["orange"],
            "ALLOW":  C["green"],
            "INFO":   C["accent"],
        }.get(action, C["text"])

    def clear_table(self):
        self.setRowCount(0)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔥 Intelligent Firewall — Command Center")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self._worker = None
        self._running = False
        self._stats = {"total": 0, "blocked": 0, "floods": 0, "attacks": 0, "allowed": 0}
        self._recent_events = deque(maxlen=500)

        self.setStyleSheet(STYLESHEET)
        self._build_menu()
        self._build_ui()
        self._build_status_bar()

        # Fixed GUI Timers scope destruction logic explicitly parenting to window runtime loop.
        self._timer = QTimer(self) 
        self._timer.timeout.connect(self._update_stats_display)
        self._timer.start(1000)

    # ── Menu Bar ──────────────────────────────────────────────────────────────
    def _build_menu(self):
        mb = self.menuBar()

        # Lambda safety - uses variadic absorption arguments handling any dynamic Pyqt triggering bugs internally
        file_menu = mb.addMenu("File")
        file_menu.addAction(self._action("Export Logs", lambda *a: self._export_logs()))
        file_menu.addAction(self._action("Clear Logs", lambda *a: self._clear_logs()))
        file_menu.addSeparator()
        file_menu.addAction(self._action("Exit", lambda *a: self.close()))

        fw_menu = mb.addMenu("Firewall")
        fw_menu.addAction(self._action("▶ Start All Stages", lambda *a: self._start_firewall()))
        fw_menu.addAction(self._action("■ Stop All Stages", lambda *a: self._stop_firewall()))
        fw_menu.addSeparator()
        fw_menu.addAction(self._action("Start Stage 1 (Packet Capture)", lambda *a: self._start_stage("Stage1")))
        fw_menu.addAction(self._action("Start Stage 5 (EDR)", lambda *a: self._start_stage("Stage5")))
        fw_menu.addAction(self._action("Start Stage 6 (Zero Trust)", lambda *a: self._start_stage("Stage6")))

        set_menu = mb.addMenu("Settings")
        set_menu.addAction(self._action("Telegram Alerts", lambda *a: self._open_telegram_settings()))
        set_menu.addAction(self._action("Logging Settings", lambda *a: self._open_log_settings()))
        set_menu.addAction(self._action("Stage Configuration", lambda *a: self._open_stage_settings()))

        pol_menu = mb.addMenu("Policies")
        pol_menu.addAction(self._action("Edit Role Policies (policies.json)", lambda *a: self._open_policy_editor()))
        pol_menu.addAction(self._action("Edit Firewall Rules", lambda *a: self._open_rules_editor()))
        pol_menu.addAction(self._action("Manage Blocked IPs", lambda *a: self._open_blocked_ips()))
        pol_menu.addAction(self._action("Manage Suspicious Keywords", lambda *a: self._open_keywords_editor()))

        tools_menu = mb.addMenu("Tools")
        tools_menu.addAction(self._action("Test Telegram Alert", lambda *a: self._test_telegram()))
        tools_menu.addAction(self._action("Send Test Event", lambda *a: self._inject_test_event()))

        help_menu = mb.addMenu("Help")
        help_menu.addAction(self._action("About", lambda *a: self._show_about()))

    def _action(self, label, slot):
        a = QAction(label, self)
        a.triggered.connect(slot)
        return a

    # ── Main UI ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # ── Top control bar ──
        ctrl_bar = self._build_control_bar()
        main_layout.addWidget(ctrl_bar)

        # ── Stats row ──
        stats_row = self._build_stats_row()
        main_layout.addWidget(stats_row)

        # ── Tab widget ──
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 1)

        self.tabs.addTab(self._build_live_tab(),       "⚡  Live Monitor")
        self.tabs.addTab(self._build_logs_tab(),       "📋  Logs")
        self.tabs.addTab(self._build_policies_tab(),   "🛡  Policies")
        self.tabs.addTab(self._build_rules_tab(),      "📏  Rules")
        self.tabs.addTab(self._build_settings_tab(),   "⚙  Settings")

    # ── Control Bar ──────────────────────────────────────────────────────────
    def _build_control_bar(self):
        bar = QFrame()
        bar.setStyleSheet(f"""
            QFrame {{
                background-color: {C['header']};
                border-bottom: 2px solid {C['accent']};
            }}
        """)
        bar.setFixedHeight(60)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 16, 0)

        # Logo / title
        title = QLabel("🔥 INTELLIGENT FIREWALL")
        title.setStyleSheet(f"color: {C['accent']}; font-size: 16px; font-weight: bold; letter-spacing: 3px; border: none; background: transparent;")
        layout.addWidget(title)

        layout.addStretch()

        # Stage status indicators
        self._stage_indicators = {}
        for stage in ["S1", "S2", "S3/4", "S5", "S6"]:
            lbl = QLabel(f"◉ {stage}")
            lbl.setStyleSheet(f"color: {C['text_dim']}; font-size: 10px; font-weight: bold; margin: 0 6px; border: none; background: transparent;")
            self._stage_indicators[stage] = lbl
            layout.addWidget(lbl)

        layout.addSpacing(20)

        self.start_btn = QPushButton("▶  START ALL")
        self.start_btn.setObjectName("start_btn")
        self.start_btn.setFixedHeight(38)
        self.start_btn.clicked.connect(self._start_firewall)

        self.stop_btn = QPushButton("■  STOP ALL")
        self.stop_btn.setObjectName("stop_btn")
        self.stop_btn.setFixedHeight(38)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_firewall)

        layout.addWidget(self.start_btn)
        layout.addSpacing(8)
        layout.addWidget(self.stop_btn)

        return bar

    def _build_stats_row(self):
        row = QFrame()
        row.setStyleSheet(f"background-color: {C['bg']}; padding: 8px 16px; border: none;")
        row.setFixedHeight(90)
        layout = QHBoxLayout(row)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 8, 16, 8)

        self.card_total   = StatCard("Total Events",   "0", C["accent"])
        self.card_allowed = StatCard("Allowed",        "0", C["green"])
        self.card_blocked = StatCard("Blocked",        "0", C["red"])
        self.card_floods  = StatCard("Flood Attacks",  "0", C["orange"])
        self.card_attacks = StatCard("EDR Detections", "0", C["yellow"])

        for card in [self.card_total, self.card_allowed, self.card_blocked,
                     self.card_floods, self.card_attacks]:
            layout.addWidget(card)

        return row

    def _build_live_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(4)
        layout.setContentsMargins(8, 8, 8, 8)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet(f"color: {C['text_dim']}; font-size: 11px;")
        self.filter_action = QComboBox()
        self.filter_action.addItems(["ALL", "BLOCK", "ALLOW", "FLOOD", "ATTACK", "ERROR"])
        self.filter_action.currentTextChanged.connect(self._apply_filter)

        self.filter_ip = QLineEdit()
        self.filter_ip.setPlaceholderText("Filter by IP...")
        self.filter_ip.setFixedWidth(160)
        self.filter_ip.textChanged.connect(self._apply_filter)

        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        # Using toggled to correctly transmit True/False rather than Enum Qt int values to bool assignments directly
        self.auto_scroll_cb.toggled.connect(
            lambda is_checked: setattr(self.log_table, '_auto_scroll', is_checked))

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self._clear_live)

        filter_bar.addWidget(filter_lbl)
        filter_bar.addWidget(self.filter_action)
        filter_bar.addWidget(QLabel("IP:"))
        filter_bar.addWidget(self.filter_ip)
        filter_bar.addStretch()
        filter_bar.addWidget(self.auto_scroll_cb)
        filter_bar.addWidget(clear_btn)
        layout.addLayout(filter_bar)

        self.log_table = LiveLogTable()
        layout.addWidget(self.log_table)

        return w

    def _build_logs_tab(self):
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setSpacing(8)
        layout.setContentsMargins(8, 8, 8, 8)

        left = QGroupBox("Log Files")
        left.setFixedWidth(220)
        left_layout = QVBoxLayout(left)
        self.log_file_list = QListWidget()
        self.log_file_list.currentRowChanged.connect(self._load_log_file)
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self._refresh_log_files)
        left_layout.addWidget(self.log_file_list)
        left_layout.addWidget(refresh_btn)
        layout.addWidget(left)

        right = QGroupBox("Log Content")
        right_layout = QVBoxLayout(right)
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setStyleSheet(f"""
            background-color: {C['header']};
            color: {C['green']};
            font-family: 'Consolas', monospace;
            font-size: 11px;
        """)
        right_layout.addWidget(self.log_viewer)

        btn_row = QHBoxLayout()
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self._export_logs)
        clear_log_btn = QPushButton("Clear All Logs")
        clear_log_btn.setObjectName("danger")
        clear_log_btn.clicked.connect(self._clear_all_logs)
        btn_row.addWidget(export_btn)
        btn_row.addWidget(clear_log_btn)
        btn_row.addStretch()
        right_layout.addLayout(btn_row)
        layout.addWidget(right, 1)

        self._refresh_log_files()
        return w

    def _build_policies_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        hdr = QLabel("🛡  IDENTITY POLICIES  —  User Role Access Control")
        hdr.setStyleSheet(f"color: {C['accent']}; font-size: 13px; font-weight: bold; letter-spacing: 1px;")
        layout.addWidget(hdr)

        role_row = QHBoxLayout()
        role_row.addWidget(QLabel("Role:"))
        self.role_selector = QComboBox()
        self.role_selector.addItems(["Admin", "Developer", "Student", "HR"])
        self.role_selector.currentTextChanged.connect(self._load_role_policy)
        role_row.addWidget(self.role_selector)
        role_row.addStretch()
        add_role_btn = QPushButton("+ Add Role")
        add_role_btn.clicked.connect(self._add_role)
        del_role_btn = QPushButton("Delete Role")
        del_role_btn.setObjectName("danger")
        del_role_btn.clicked.connect(self._delete_role)
        role_row.addWidget(add_role_btn)
        role_row.addWidget(del_role_btn)
        layout.addLayout(role_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        domain_grp = QGroupBox("Allowed Domains")
        domain_layout = QVBoxLayout(domain_grp)
        self.domain_list = QListWidget()
        domain_layout.addWidget(self.domain_list)
        d_btns = QHBoxLayout()
        self.new_domain = QLineEdit()
        self.new_domain.setPlaceholderText("e.g. github.com")
        add_d = QPushButton("Add")
        add_d.clicked.connect(self._add_domain)
        del_d = QPushButton("Remove")
        del_d.setObjectName("danger")
        del_d.clicked.connect(self._del_domain)
        d_btns.addWidget(self.new_domain)
        d_btns.addWidget(add_d)
        d_btns.addWidget(del_d)
        domain_layout.addLayout(d_btns)
        splitter.addWidget(domain_grp)

        port_grp = QGroupBox("Blocked Ports")
        port_layout = QVBoxLayout(port_grp)
        self.port_list = QListWidget()
        port_layout.addWidget(self.port_list)
        p_btns = QHBoxLayout()
        self.new_port = QSpinBox()
        self.new_port.setRange(1, 65535)
        add_p = QPushButton("Add")
        add_p.clicked.connect(self._add_port)
        del_p = QPushButton("Remove")
        del_p.setObjectName("danger")
        del_p.clicked.connect(self._del_port)
        p_btns.addWidget(self.new_port)
        p_btns.addWidget(add_p)
        p_btns.addWidget(del_p)
        port_layout.addLayout(p_btns)
        splitter.addWidget(port_grp)

        layout.addWidget(splitter, 1)

        save_btn = QPushButton("💾  Save Policies")
        save_btn.setObjectName("success")
        save_btn.clicked.connect(self._save_policies)
        layout.addWidget(save_btn)

        self._load_role_policy("Admin")
        return w

    def _build_rules_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        hdr = QLabel("📏  FIREWALL RULES  —  Stage 2 Rule Engine")
        hdr.setStyleSheet(f"color: {C['accent']}; font-size: 13px; font-weight: bold; letter-spacing: 1px;")
        layout.addWidget(hdr)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        ip_grp = QGroupBox("Blocked IPs")
        ip_layout = QVBoxLayout(ip_grp)
        self.blocked_ip_list = QListWidget()
        ip_layout.addWidget(self.blocked_ip_list)
        ip_btns = QHBoxLayout()
        self.new_ip = QLineEdit()
        self.new_ip.setPlaceholderText("e.g. 1.2.3.4")
        add_ip = QPushButton("Add")
        add_ip.clicked.connect(self._add_blocked_ip)
        del_ip = QPushButton("Remove")
        del_ip.setObjectName("danger")
        del_ip.clicked.connect(self._del_blocked_ip)
        ip_btns.addWidget(self.new_ip)
        ip_btns.addWidget(add_ip)
        ip_btns.addWidget(del_ip)
        ip_layout.addLayout(ip_btns)
        splitter.addWidget(ip_grp)

        bport_grp = QGroupBox("Blocked Ports (Global)")
        bport_layout = QVBoxLayout(bport_grp)
        self.global_port_list = QListWidget()
        bport_layout.addWidget(self.global_port_list)
        bp_btns = QHBoxLayout()
        self.new_gport = QSpinBox()
        self.new_gport.setRange(1, 65535)
        add_bp = QPushButton("Add")
        add_bp.clicked.connect(self._add_global_port)
        del_bp = QPushButton("Remove")
        del_bp.setObjectName("danger")
        del_bp.clicked.connect(self._del_global_port)
        bp_btns.addWidget(self.new_gport)
        bp_btns.addWidget(add_bp)
        bp_btns.addWidget(del_bp)
        bport_layout.addLayout(bp_btns)
        splitter.addWidget(bport_grp)

        flood_grp = QGroupBox("Flood Detection")
        flood_layout = QFormLayout(flood_grp)
        self.flood_spin = QSpinBox()
        self.flood_spin.setRange(10, 10000)
        self.flood_spin.setValue(100)
        flood_layout.addRow("Threshold (pkt/s):", self.flood_spin)
        splitter.addWidget(flood_grp)

        layout.addWidget(splitter, 1)

        save_rules_btn = QPushButton("💾  Save Rules")
        save_rules_btn.setObjectName("success")
        save_rules_btn.clicked.connect(self._save_rules)
        layout.addWidget(save_rules_btn)

        self._load_rules_ui()
        return w

    def _build_settings_tab(self):
        w = QScrollArea()
        w.setWidgetResizable(True)
        inner = QWidget()
        w.setWidget(inner)
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        tg_grp = QGroupBox("🔔 Telegram Alerts")
        tg_form = QFormLayout(tg_grp)

        self.tg_enabled = QCheckBox("Enable Telegram Alerts")
        self.tg_token = QLineEdit()
        self.tg_token.setPlaceholderText("Bot token from @BotFather")
        self.tg_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.tg_chat_id = QLineEdit()
        self.tg_chat_id.setPlaceholderText("Your Telegram chat ID")

        self.tg_alert_block  = QCheckBox("Alert on BLOCK")
        self.tg_alert_flood  = QCheckBox("Alert on FLOOD")
        self.tg_alert_attack = QCheckBox("Alert on ATTACK")
        self.tg_alert_edr    = QCheckBox("Alert on EDR Detection")

        tg_form.addRow("", self.tg_enabled)
        tg_form.addRow("Bot Token:", self.tg_token)
        tg_form.addRow("Chat ID:", self.tg_chat_id)
        tg_form.addRow("", self.tg_alert_block)
        tg_form.addRow("", self.tg_alert_flood)
        tg_form.addRow("", self.tg_alert_attack)
        tg_form.addRow("", self.tg_alert_edr)

        tg_btns = QHBoxLayout()
        test_tg = QPushButton("📨 Test Telegram")
        test_tg.clicked.connect(self._test_telegram)
        save_tg = QPushButton("💾 Save")
        save_tg.clicked.connect(self._save_telegram_settings)
        tg_btns.addWidget(test_tg)
        tg_btns.addWidget(save_tg)
        tg_btns.addStretch()
        tg_form.addRow("", tg_btns)

        layout.addWidget(tg_grp)

        log_grp = QGroupBox("📋 Logging Settings")
        log_form = QFormLayout(log_grp)
        self.log_enabled_cb = QCheckBox("Enable file logging")
        self.log_enabled_cb.setChecked(True)
        # Fix mapping raw toggled parameters universally
        self.log_enabled_cb.toggled.connect(self._toggle_logging) 
        log_form.addRow("", self.log_enabled_cb)

        log_dir_row = QHBoxLayout()
        self.log_dir_lbl = QLabel(os.path.join(ROOT, "logs"))
        self.log_dir_lbl.setStyleSheet(f"color: {C['text_dim']};")
        open_log_btn = QPushButton("Open Folder")
        open_log_btn.clicked.connect(self._open_log_folder)
        log_dir_row.addWidget(self.log_dir_lbl)
        log_dir_row.addWidget(open_log_btn)
        log_form.addRow("Log Directory:", log_dir_row)
        layout.addWidget(log_grp)

        kw_grp = QGroupBox("🔍 Suspicious Keywords (Stage 5 EDR)")
        kw_layout = QVBoxLayout(kw_grp)
        self.kw_text = QTextEdit()
        self.kw_text.setFixedHeight(120)
        self.kw_text.setPlaceholderText("One keyword per line")
        self._load_keywords()
        save_kw = QPushButton("💾 Save Keywords")
        save_kw.clicked.connect(self._save_keywords)
        kw_layout.addWidget(self.kw_text)
        kw_layout.addWidget(save_kw)
        layout.addWidget(kw_grp)

        layout.addStretch()
        self._load_telegram_settings()
        return w

    # ── Status Bar ────────────────────────────────────────────────────────────
    def _build_status_bar(self):
        sb = self.statusBar()
        self.status_lbl = QLabel("● STOPPED  |  All stages inactive")
        self.status_lbl.setStyleSheet(f"color: {C['text_dim']}; font-size: 10px; padding: 2px 8px;")
        sb.addWidget(self.status_lbl)

        self.time_lbl = QLabel()
        self.time_lbl.setStyleSheet(f"color: {C['text_dim']}; font-size: 10px; padding: 2px 8px;")
        sb.addPermanentWidget(self.time_lbl)

        # BugFix Parent timer object otherwise execution destroys instantly breaking standard updates!
        self._time_timer = QTimer(self) 
        self._time_timer.timeout.connect(self._update_time)
        self._time_timer.start(1000)

    # ════════════════════════════════════════════════════════════════
    # CONTROL ACTIONS
    # ════════════════════════════════════════════════════════════════
    def _start_firewall(self):
        if self._running or (self._worker and self._worker.isRunning()):
            return
        self._running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText("● RUNNING  |  All stages active")
        self.status_lbl.setStyleSheet(f"color: {C['green']}; font-size: 10px; padding: 2px 8px;")

        self._worker = FirewallWorker()
        self._worker.event_received.connect(self._on_event)
        self._worker.status_changed.connect(self._on_status)
        self._worker.start()

    def _stop_firewall(self):
        if not self._running:
            return
        self._running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("● STOPPED  |  All stages inactive")
        self.status_lbl.setStyleSheet(f"color: {C['text_dim']}; font-size: 10px; padding: 2px 8px;")
        
        # Stop cleanly rather than aggressively severing class links forcing errors
        if self._worker:
            self._worker.stop()
            # Delete properly off active tasks internally upon loop finish rather than freezing current app here 

    def _start_stage(self, name):
        try:
            from orchestrator import start_stage
            start_stage(name)
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Module might be absent:\n\n{str(e)}")

    def _on_event(self, event: dict):
        action = event.get("action", "")
        self._recent_events.append(event)

        self._stats["total"] += 1
        if action == "BLOCK":
            self._stats["blocked"] += 1
        elif action == "ALLOW":
            self._stats["allowed"] += 1
        elif action == "FLOOD":
            self._stats["floods"] += 1
        elif action == "ATTACK":
            self._stats["attacks"] += 1

        if self._event_passes_filter(event):
            self.log_table.add_event(event)

    def _on_status(self, status: dict):
        colors = {True: C["green"], False: C["text_dim"]}
        stage_map = {
            "Stage1": "S1", "Stage2": "S2",
            "Stage3_4": "S3/4", "Stage5": "S5", "Stage6": "S6"
        }
        for key, short in stage_map.items():
            active = status.get(key, False)
            lbl = self._stage_indicators.get(short)
            if lbl:
                lbl.setStyleSheet(
                    f"color: {colors.get(active, C['text_dim'])}; font-size: 10px; "
                    f"font-weight: bold; margin: 0 6px; border: none; background: transparent;"
                )

    def _event_passes_filter(self, event):
        action_filter = self.filter_action.currentText() if hasattr(self, 'filter_action') else "ALL"
        ip_filter = self.filter_ip.text().strip() if hasattr(self, 'filter_ip') else ""

        if action_filter != "ALL" and event.get("action") != action_filter:
            return False
        if ip_filter:
            src = str(event.get("src_ip", ""))
            dst = str(event.get("dst_ip", ""))
            if ip_filter not in src and ip_filter not in dst:
                return False
        return True

    def _apply_filter(self):
        self.log_table.clear_table()
        for event in self._recent_events:
            if self._event_passes_filter(event):
                self.log_table.add_event(event)

    def _clear_live(self):
        self.log_table.clear_table()

    def _update_stats_display(self):
        self.card_total.set_value(self._stats["total"])
        self.card_allowed.set_value(self._stats["allowed"])
        self.card_blocked.set_value(self._stats["blocked"])
        self.card_floods.set_value(self._stats["floods"])
        self.card_attacks.set_value(self._stats["attacks"])

    def _update_time(self):
        self.time_lbl.setText(datetime.now().strftime("  %Y-%m-%d  %H:%M:%S  "))

    # ════════════════════════════════════════════════════════════════
    # POLICIES
    # ════════════════════════════════════════════════════════════════
    def _policies_path(self):
        return os.path.join(ROOT, "Stage6_ZeroTrust", "policies.json")

    def _load_policies(self):
        try:
            with open(self._policies_path()) as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_role_policy(self, role=None):
        role = role or self.role_selector.currentText()
        policies = self._load_policies()
        pol = policies.get(role, {"allowed_domains": [], "blocked_ports": []})

        self.domain_list.clear()
        for d in pol.get("allowed_domains", []):
            self.domain_list.addItem(str(d))

        self.port_list.clear()
        for p in pol.get("blocked_ports", []):
            self.port_list.addItem(str(p))

    def _save_policies(self):
        role = self.role_selector.currentText()
        policies = self._load_policies()
        policies[role] = {
            "allowed_domains": [self.domain_list.item(i).text() for i in range(self.domain_list.count())],
            "blocked_ports": [int(self.port_list.item(i).text()) for i in range(self.port_list.count())]
        }
        
        path = self._policies_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)  # Fix potential FileNotFound crashing app  
        with open(path, "w") as f:
            json.dump(policies, f, indent=2)
        QMessageBox.information(self, "Saved", f"Policies for role '{role}' saved.")

    def _add_domain(self):
        d = self.new_domain.text().strip()
        if d:
            self.domain_list.addItem(d)
            self.new_domain.clear()

    def _del_domain(self):
        for item in self.domain_list.selectedItems():
            self.domain_list.takeItem(self.domain_list.row(item))

    def _add_port(self):
        self.port_list.addItem(str(self.new_port.value()))

    def _del_port(self):
        for item in self.port_list.selectedItems():
            self.port_list.takeItem(self.port_list.row(item))

    def _add_role(self):
        name, ok = QInputDialog.getText(self, "New Role", "Role name:")
        if ok and name:
            policies = self._load_policies()
            if name not in policies:
                policies[name] = {"allowed_domains": [], "blocked_ports": []}
                
                path = self._policies_path()
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    json.dump(policies, f, indent=2)
                    
                self.role_selector.addItem(name)
                self.role_selector.setCurrentText(name)

    def _delete_role(self):
        role = self.role_selector.currentText()
        if role in ("Admin", "Developer", "Student", "HR"):
            QMessageBox.warning(self, "Error", "Cannot delete built-in roles.")
            return
            
        policies = self._load_policies()
        policies.pop(role, None)
        
        path = self._policies_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(policies, f, indent=2)
            
        idx = self.role_selector.currentIndex()
        self.role_selector.removeItem(idx)

    # ════════════════════════════════════════════════════════════════
    # RULES
    # ════════════════════════════════════════════════════════════════
    def _rules_path(self):
        return os.path.join(ROOT, "Stage2_RuleEngine", "firewall_rules.json")

    def _load_rules_data(self):
        try:
            with open(self._rules_path()) as f:
                return json.load(f)
        except Exception:
            return {"blocked_ips": [], "blocked_ports": [], "flood_threshold": 100, "rules": []}

    def _load_rules_ui(self):
        data = self._load_rules_data()
        self.blocked_ip_list.clear()
        for ip in data.get("blocked_ips", []):
            self.blocked_ip_list.addItem(str(ip))
        self.global_port_list.clear()
        for p in data.get("blocked_ports", []):
            self.global_port_list.addItem(str(p))
        self.flood_spin.setValue(int(data.get("flood_threshold", 100)))

    def _save_rules(self):
        data = self._load_rules_data()
        data["blocked_ips"] = [self.blocked_ip_list.item(i).text() for i in range(self.blocked_ip_list.count())]
        data["blocked_ports"] = [int(self.global_port_list.item(i).text()) for i in range(self.global_port_list.count())]
        data["flood_threshold"] = self.flood_spin.value()
        
        path = self._rules_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)  # Fix fileNotFound crash bounds   
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        QMessageBox.information(self, "Saved", "Firewall rules saved.")

    def _add_blocked_ip(self):
        ip = self.new_ip.text().strip()
        if ip:
            self.blocked_ip_list.addItem(ip)
            self.new_ip.clear()

    def _del_blocked_ip(self):
        for item in self.blocked_ip_list.selectedItems():
            self.blocked_ip_list.takeItem(self.blocked_ip_list.row(item))

    def _add_global_port(self):
        self.global_port_list.addItem(str(self.new_gport.value()))

    def _del_global_port(self):
        for item in self.global_port_list.selectedItems():
            self.global_port_list.takeItem(self.global_port_list.row(item))

    # ════════════════════════════════════════════════════════════════
    # SETTINGS — Telegram
    # ════════════════════════════════════════════════════════════════
    def _load_telegram_settings(self):
        try:
            from telegram_alert import load_config
            cfg = load_config()
            self.tg_enabled.setChecked(cfg.get("enabled", False))
            self.tg_token.setText(cfg.get("bot_token", ""))
            self.tg_chat_id.setText(cfg.get("chat_id", ""))
            self.tg_alert_block.setChecked(cfg.get("alert_on_block", True))
            self.tg_alert_flood.setChecked(cfg.get("alert_on_flood", True))
            self.tg_alert_attack.setChecked(cfg.get("alert_on_attack", True))
            self.tg_alert_edr.setChecked(cfg.get("alert_on_edr", True))
        except ImportError:
            pass # Standard backend missing scenario handler

    def _save_telegram_settings(self):
        try:
            from telegram_alert import load_config, save_config
            cfg = load_config()
            cfg["enabled"]        = self.tg_enabled.isChecked()
            cfg["bot_token"]      = self.tg_token.text().strip()
            cfg["chat_id"]        = self.tg_chat_id.text().strip()
            cfg["alert_on_block"] = self.tg_alert_block.isChecked()
            cfg["alert_on_flood"] = self.tg_alert_flood.isChecked()
            cfg["alert_on_attack"]= self.tg_alert_attack.isChecked()
            cfg["alert_on_edr"]   = self.tg_alert_edr.isChecked()
            save_config(cfg)
            QMessageBox.information(self, "Saved", "Telegram settings saved.")
        except ImportError:
             QMessageBox.warning(self, "Settings Warning", "Standalone environment missing 'telegram_alert.py' modules!")

    def _test_telegram(self):
        try:
            from telegram_alert import send_test_message
            ok, msg = send_test_message()
            if ok:
                QMessageBox.information(self, "Telegram Test", f"✅ {msg}")
            else:
                QMessageBox.warning(self, "Telegram Test", f"❌ {msg}")
        except Exception as e:
            QMessageBox.warning(self, "Missing Environment Warning", str(e))

    def _open_telegram_settings(self):
        self.tabs.setCurrentIndex(4)

    # ════════════════════════════════════════════════════════════════
    # SETTINGS — Logging
    # ════════════════════════════════════════════════════════════════
    def _toggle_logging(self, is_checked: bool):
        try:
            from event_bus import set_logging
            set_logging(is_checked)
        except ImportError:
            pass 

    def _open_log_folder(self):
        log_dir = os.path.join(ROOT, "logs")
        os.makedirs(log_dir, exist_ok=True)
        # Using strict QT API logic solving rigid cross-system open crashes globally  
        QDesktopServices.openUrl(QUrl.fromLocalFile(log_dir))

    def _open_log_settings(self):
        self.tabs.setCurrentIndex(4)

    # ════════════════════════════════════════════════════════════════
    # LOG FILE VIEWER
    # ════════════════════════════════════════════════════════════════
    def _refresh_log_files(self):
        try:
            from event_bus import get_all_log_files
            files = get_all_log_files()
        except ImportError:
            log_dir = os.path.join(ROOT, "logs")
            files = sorted([
                os.path.join(log_dir, f)
                for f in os.listdir(log_dir)
                if f.endswith(".log")
            ], reverse=True) if os.path.exists(log_dir) else []

        self.log_file_list.clear()
        for f in files:
            item = QListWidgetItem(os.path.basename(f))
            item.setData(Qt.ItemDataRole.UserRole, f)
            self.log_file_list.addItem(item)

    def _load_log_file(self, idx):
        item = self.log_file_list.item(idx)
        if not item:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-500:]
            text = ""
            for line in lines:
                try:
                    ev = json.loads(line.strip())
                    action = ev.get("action", "")
                    color_map = {"BLOCK": "red", "FLOOD": "orange", "ATTACK": "red",
                                 "ALLOW": "lime", "INFO": "cyan", "ERROR": "orange"}
                    col = color_map.get(action, "white")
                    text += (f'<span style="color:{col}">'
                             f'[{ev.get("timestamp","")}] [{ev.get("stage","")}] '
                             f'{action} | {ev.get("src_ip","")} → {ev.get("dst_ip","")} '
                             f'| {str(ev.get("reason",""))}</span><br>')
                except Exception:
                    text += f'<span style="color:#aaa">{line.strip()}</span><br>'
            self.log_viewer.setHtml(f'<div style="font-family:Consolas;font-size:11px">{text}</div>')
        except Exception as e:
            self.log_viewer.setText(str(e))

    def _export_logs(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "firewall_export.json", "JSON Files (*.json);;All Files (*)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(list(self._recent_events), f, indent=2)
                QMessageBox.information(self, "Exported", f"Logs exported to {path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _clear_logs(self):
        self._recent_events.clear()
        self.log_table.clear_table()
        self._stats = {"total": 0, "blocked": 0, "floods": 0, "attacks": 0, "allowed": 0}

    def _clear_all_logs(self):
        reply = QMessageBox.question(self, "Confirm", "Delete all log files?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            log_dir = os.path.join(ROOT, "logs")
            if os.path.exists(log_dir):
                for f in os.listdir(log_dir):
                    if f.endswith(".log"):
                        os.remove(os.path.join(log_dir, f))
            self._refresh_log_files()
            self.log_viewer.clear()

    # ════════════════════════════════════════════════════════════════
    # KEYWORDS
    # ════════════════════════════════════════════════════════════════
    def _keywords_path(self):
        return os.path.join(ROOT, "Stage5_EDR", "detection_rules.py")

    def _load_keywords(self):
        try:
            path = self._keywords_path()
            with open(path) as f:
                content = f.read()
            import re
            match = re.search(r'SUSPICIOUS_KEYWORDS\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                kws = re.findall(r'"([^"]+)"', match.group(1))
                self.kw_text.setPlainText("\n".join(kws))
        except Exception:
            self.kw_text.setPlainText("powershell\n-enc\niex\ndownloadstring\ncertutil")

    def _save_keywords(self):
        QMessageBox.information(self, "Info",
            "To change detection keywords, edit:\n"
            f"{self._keywords_path()}\n\n"
            "Update the SUSPICIOUS_KEYWORDS list and restart the firewall.")

    def _open_keywords_editor(self):
        self.tabs.setCurrentIndex(4)

    # ════════════════════════════════════════════════════════════════
    # DIALOG LAUNCHERS
    # ════════════════════════════════════════════════════════════════
    def _open_policy_editor(self):
        self.tabs.setCurrentIndex(2)

    def _open_rules_editor(self):
        self.tabs.setCurrentIndex(3)

    def _open_blocked_ips(self):
        self.tabs.setCurrentIndex(3)

    def _open_stage_settings(self):
        self.tabs.setCurrentIndex(4)

    def _inject_test_event(self):
        """Inject a fake event safely handling decoupled core integrations."""
        fake_payload = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "stage": "TEST",
            "action": "BLOCK",
            "src_ip": "192.168.1.99",
            "dst_ip": "1.2.3.4",
            "port": 4444,
            "protocol": "TCP",
            "reason": "Test block event from GUI module interaction."
        }
        try:
            from event_bus import emit
            emit(fake_payload)
        except ImportError:
            self._on_event(fake_payload) # Puts events in table beautifully despite environment 

    def _show_about(self):
        QMessageBox.information(self, "About — Intelligent Firewall",
            "🔥 Intelligent Firewall\n\n"
            "6-Stage Network Security System\n\n"
            "Stage 1: Packet Capture (Scapy)\n"
            "Stage 2: Rule Engine\n"
            "Stage 3/4: NGFW + ML (XGBoost)\n"
            "Stage 5: EDR / LotL Detection (Sysmon)\n"
            "Stage 6: Zero Trust (Identity + Microseg)\n\n"
            "Built with PyQt6\n"
            "Telegram alert integration included"
        )

    def closeEvent(self, event):
        self._stop_firewall()
        event.accept()

# ─── Entry point ──────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Intelligent Firewall")
    app.setStyle("Fusion")

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()