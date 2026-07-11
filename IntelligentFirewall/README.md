# 🔥 Intelligent Firewall — 6-Stage Network Security System

## Folder Structure

```
IntelligentFirewall/
│
├── run.py                          ← ONE COMMAND LAUNCHER
│
├── Stage1_PacketCapture/
│   └── packet_capture.py           ← Scapy live packet capture
│
├── Stage2_RuleEngine/
│   ├── rule_engine.py              ← Rule-based filtering + flood detection
│   └── firewall_rules.json         ← Editable rules (IPs, ports, thresholds)
│
├── Stage3_4_NGFW_ML/
│   ├── ngfw_engine.py              ← mitmproxy NGFW + ML inference
│   ├── combine_ngfw_dataset.py     ← Dataset combiner (CICIDS2017 + UNSW-NB15)
│   ├── step1_accuracy_model.py     ← Model accuracy check
│   ├── step2_preprocess_train_model.py  ← Train & save XGBoost model
│   └── test_model.py               ← Test mitmproxy ML engine
│
├── Stage5_EDR/
│   ├── main_stage5.py              ← EDR entry point
│   ├── sysmon_monitor.py           ← Windows Sysmon event reader
│   ├── detection_rules.py          ← LotL / LOLBins detection rules
│   ├── network_monitor.py          ← Per-process connection tracking
│   ├── network_mapper.py           ← IP mapping helper
│   └── response_engine.py          ← Kill process + block IP actions
│
├── Stage6_ZeroTrust/
│   ├── main_stage6.py              ← Zero Trust entry point + live monitor
│   ├── identity_policy.py          ← User/role-based access control
│   ├── microsegmentation.py        ← Zone-to-zone traffic rules
│   ├── default_deny.py             ← Whitelist enforcement
│   ├── sandbox.py                  ← File/URL sandbox analysis
│   └── policies.json               ← Role policies (edit via GUI)
│
├── Core/
│   ├── orchestrator.py             ← Launches all stages in threads
│   ├── event_bus.py                ← Central event emitter + log writer
│   └── telegram_alert.py          ← Telegram Bot integration
│
├── GUI/
│   └── firewall_gui.py             ← PyQt6 Dashboard
│
└── logs/                           ← Auto-created daily log files
```

---

## Quick Start — ONE COMMAND

```bash
# 1. Install dependencies (once)
pip install PyQt6 scapy psutil pywin32 pyqt6

# 2. Launch everything (GUI + all stages)
python run.py

# 3. Console-only mode (no GUI)
python run.py --cli

# 4. Run Stage 6 tests only
python run.py --test
```

---

## Stage Requirements

| Stage | Requires |
|-------|---------|
| Stage 1 (Packet Capture) | `scapy`, run as Administrator |
| Stage 2 (Rule Engine) | Built-in, no extra deps |
| Stage 3/4 (NGFW+ML) | `mitmproxy`, `joblib`, `xgboost`, trained model files |
| Stage 5 (EDR) | Windows only, `pywin32`, Sysmon installed |
| Stage 6 (Zero Trust) | `psutil` |
| GUI | `PyQt6` |
| Telegram | Bot token + chat ID configured in Settings tab |

---

## Telegram Setup (Step by Step)

1. Open Telegram → search for **@BotFather**
2. Send `/newbot` → follow steps → copy your **Bot Token**
3. Start a chat with your bot
4. Open: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
5. Copy your **chat_id** from the JSON response
6. In the GUI → **Settings tab** → paste Token + Chat ID → click **Save**
7. Click **Test Telegram** to verify

---

## GUI Features

| Feature | Location |
|---------|---------|
| Start/Stop all stages | Top control bar |
| Live packet/event table with filters | Live Monitor tab |
| Action filter (BLOCK/ALLOW/FLOOD...) | Live Monitor tab |
| IP filter | Live Monitor tab |
| Daily log files viewer | Logs tab |
| Export logs to JSON | File menu / Logs tab |
| Edit role policies (domains + ports) | Policies tab |
| Add/remove blocked IPs | Rules tab |
| Add/remove blocked ports | Rules tab |
| Set flood threshold | Rules tab |
| Telegram alert settings | Settings tab |
| Toggle file logging on/off | Settings tab |
| Test Telegram connection | Settings tab / Tools menu |
| Inject test event | Tools menu |
| Stage status indicators | Top bar (S1–S6) |

---

## Adding/Editing Policies

Use the **Policies tab** in the GUI, or edit `Stage6_ZeroTrust/policies.json` directly:

```json
{
  "Admin":     { "allowed_domains": ["*"],  "blocked_ports": [] },
  "Developer": { "allowed_domains": ["github.com", "google.com"], "blocked_ports": [21, 23] },
  "NewRole":   { "allowed_domains": ["example.com"], "blocked_ports": [21, 22, 23] }
}
```

---

## ML Model (Stage 3/4)

1. Place CICIDS2017 CSVs in `Stage3_4_NGFW_ML/CICIDS2017/`
2. Run `python Stage3_4_NGFW_ML/combine_ngfw_dataset.py`
3. Run `python Stage3_4_NGFW_ML/step2_preprocess_train_model.py`
4. Model saved to `models/` — used by `ngfw_engine.py` via mitmproxy

---

## Notes

- Stages 1, 5 require **Administrator / elevated privileges** on Windows
- Stage 5 requires **Sysmon** to be installed and running
- Stage 3/4 mitmproxy runs separately (not in the GUI thread) — start with:
  `mitmdump -s Stage3_4_NGFW_ML/ngfw_engine.py`
- All stages are crash-isolated — one stage failing won't stop others
