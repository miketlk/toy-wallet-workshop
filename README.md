# Toy Wallet Workshop

This repository contains workshop materials and labs for hands-on security analysis of a toy hardware wallet running on RP2040 dev board (Raspberry Pi Pico).

## EDUCATIONAL USE DISCLAIMER

**AUTHORIZED ACTIVITY**
Participants are authorized to analyze, test, and intentionally interact with security weaknesses **only** in the hardware, firmware, and materials provided as part of this workshop.

**LIMITED SCOPE**
This authorization applies solely to designated workshop exercises and equipment.
Techniques discussed or demonstrated must be used **only where lawful and with proper authorization**.

**WORKSHOP EQUIPMENT**
Workshop devices are provided for hands-on experimentation.
Devices may be modified, stressed, or rendered inoperable as part of the exercises.

**PERSONAL SYSTEM RESPONSIBILITY**
Participants are responsible for the safety, integrity, and security of their **personal laptops, software, operating systems, and data**.

**ETHICAL & LAWFUL USE**
Participants agree to apply acquired knowledge responsibly, ethically, and in compliance with applicable laws.

**ACCEPTANCE OF TERMS**
Participation in the workshop constitutes acknowledgment and acceptance of this disclaimer.

## Repository Layout

- `labs/`: Guided exercises and attack labs
- `client/`: USB/client-side interaction scripts

## Labs

Follow the labs in order:

1. [Lab 1: Timing Side-Channel PIN Recovery](labs/lab1_side_channel.md)
2. [Lab 2: Flash Memory Over-Read and Function Pointer Leak](labs/lab2_bufer_overread.md)
3. [Lab 3: Remote Stack Overflow and Return Address Hijack](labs/lab3_stack_overflow.md)
4. [Lab 4 (Bonus): ROP Exploitation to Print Attacker-Controlled String](labs/lab4_bonus_rop.md)

## Workshop Machine Setup

Use the platform-specific steps below to install Python 3.10 (latest patch), create a virtual environment, and install Python dependencies.

### macOS

```bash
brew update
brew install python@3.10

python3.10 --version
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux (Ubuntu)

```bash
sudo apt update
sudo apt install -y python3.10 python3.10-venv

python3.10 --version
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (Native, PowerShell)

1. Install Python 3.10 (latest patch) from https://www.python.org/downloads/windows/
2. During install, enable `Add python.exe to PATH`.
3. In PowerShell, run:

```powershell
py -3.10 --version
py -3.10 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Verify Setup

```bash
python --version
pip list
pytest --version
```

## Hardware Setup

1. Connect the RP2040 dev board (Raspberry Pi Pico) to your laptop using your own or provided USB-C data cable.
2. Wait a few seconds for USB enumeration to complete.
3. Confirm that **two USB CDC serial interfaces** are visible and accessible from user space.

### macOS

Check for two serial devices:

```bash
ls /dev/cu.usbmodem*
```

You should see two entries (names vary by machine).

Quick access check from Python:

```bash
python -m serial.tools.list_ports -v
```

### Linux (Ubuntu)

Check kernel detection:

```bash
dmesg | tail -n 40
```

Check for two serial devices:

```bash
ls /dev/ttyACM*
```

You should see two entries (for example `/dev/ttyACM0` and `/dev/ttyACM1`).

If permissions are denied, add your user to `dialout` and re-login:

```bash
sudo usermod -a -G dialout $USER
```

Quick access check from Python:

```bash
python -m serial.tools.list_ports -v
```

### Windows (Native)

1. Connect the board and confirm Windows sees two COM ports in **Device Manager -> Ports (COM & LPT)**.
2. In PowerShell, list serial ports:

```powershell
mode
```

3. Check from Python that ports are visible to user-space programs:

```powershell
python -m serial.tools.list_ports -v
```

## UX Console (`client/ux.py`)

`client/ux.py` is a minimal serial console for the device UX/log channel (CDC 0), intended as a lightweight replacement for `screen` on macOS, Linux, and Windows.

- If run without a port argument, it auto-discovers the toy wallet by VID/PID and selects CDC 0.
- During discovery it treats any interface that responds to `ping` with `ok` as CDC 1 (host protocol), then uses the other interface as CDC 0.
- Interactive mode streams CDC 0 output and forwards your key presses to the device.
- Exit shortcut: `Ctrl-]`

Examples:

Linux/macOS auto-discovery:

```bash
python3 client/ux.py
```

Linux explicit CDC0 port:

```bash
python3 client/ux.py /dev/ttyACM0
```

macOS explicit CDC0 port:

```bash
python3 client/ux.py /dev/cu.usbmodem2101
```

Windows (PowerShell) auto-discovery:

```powershell
python client/ux.py
```

Windows explicit CDC0 port:

```powershell
python client/ux.py COM5
```

Optional tuning flags:

```bash
python3 client/ux.py --vid 0xCAFE --pid 0x4002 --banner-pulse 0.5
```

## Quick Troubleshooting

- Use a known good **data** USB-C cable; many charging cables do not expose data lines.
- Avoid USB hubs at first; plug directly into the laptop.
- Reconnect the board and rerun the port listing commands.
- If Linux shows permission errors, verify `dialout` group membership and re-login.
- If Windows does not show COM ports, reconnect the board and recheck Device Manager.
