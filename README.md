# Reconstructing Hardware Wallet Exploits

This repository contains workshop materials and labs for hands-on security analysis of a toy hardware wallet running on RP2040 dev board (Raspberry Pi Pico).

## Disclaimer

<pre>
AUTHORIZED ACTIVITY
Participants are authorized to analyze, test, and intentionally interact with security weaknesses ONLY in the hardware, firmware, and materials provided as part of this workshop.

LIMITED SCOPE
This authorization applies solely to designated workshop exercises and equipment. Techniques discussed or demonstrated must be used only where lawful and with proper authorization.

WORKSHOP EQUIPMENT
Workshop devices are provided for hands-on experimentation. Devices may be modified, stressed, or rendered inoperable as part of the exercises.

PERSONAL SYSTEM RESPONSIBILITY
Participants are responsible for the safety, integrity, and security of their personal computers, software, operating systems, and data.

ETHICAL & LAWFUL USE
Participants agree to apply acquired knowledge responsibly, ethically, and in compliance with applicable laws.

ACCEPTANCE OF TERMS
Participation in the workshop constitutes acknowledgment and acceptance of this disclaimer.
</pre>

## Contents
- [Reconstructing Hardware Wallet Exploits](#reconstructing-hardware-wallet-exploits)
  - [Disclaimer](#disclaimer)
  - [Contents](#contents)
  - [Intro](#intro)
  - [Repository Layout](#repository-layout)
  - [Labs](#labs)
  - [Workshop Machine Setup](#workshop-machine-setup)
    - [macOS](#macos)
    - [Linux (Ubuntu)](#linux-ubuntu)
    - [Windows (Native, PowerShell)](#windows-native-powershell)
    - [Verify Setup](#verify-setup)
  - [Flashing Your Own RP2040 Board](#flashing-your-own-rp2040-board)
    - [macOS](#macos-1)
    - [Linux (Ubuntu)](#linux-ubuntu-1)
    - [Windows (Native, PowerShell)](#windows-native-powershell-1)
  - [Hardware Setup](#hardware-setup)
    - [macOS](#macos-2)
    - [Linux (Ubuntu)](#linux-ubuntu-2)
    - [Windows (Native)](#windows-native)
  - [UX Console (`client/ux.py`)](#ux-console-clientuxpy)
  - [Quick Troubleshooting](#quick-troubleshooting)

## Intro

This workshop reconstructs a realistic exploit chain against intentionally vulnerable wallet firmware: a timing side-channel to recover the PIN, a buffer over-read to leak internal memory, and a stack overflow to hijack control flow (`ret2win`). Plus a bonus ROP lab for code-reuse exploitation. The goal is to understand how implementation bugs in protocol parsing and state handling become practical attacks. And also how to mitigate them with constant-time checks, strict bounds validation, and safer serialization.

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

## Flashing Your Own RP2040 Board

Use the prebuilt workshop firmware at `bin/toy_wallet.uf2` to flash your board.

1. Disconnect the RP2040 board from USB.
2. Press and hold the **BOOTSEL** button.
3. While holding **BOOTSEL**, plug the board into USB, then release the button.
4. A mass-storage drive named `RPI-RP2` should appear.
5. Copy `bin/toy_wallet.uf2` to that drive.
6. Wait for the board to reboot automatically (the `RPI-RP2` drive will disappear).

### macOS

```bash
cp bin/toy_wallet.uf2 /Volumes/RPI-RP2/
```

### Linux (Ubuntu)

Copy the file to the mounted `RPI-RP2` drive using your file manager, or from terminal:

```bash
cp bin/toy_wallet.uf2 /media/$USER/RPI-RP2/
```

### Windows (Native, PowerShell)

1. Open File Explorer and locate the `RPI-RP2` drive.
2. Copy `bin/toy_wallet.uf2` from this repository onto that drive.
3. Wait for automatic reboot.

After reboot, continue with the Hardware Setup steps below to verify USB CDC interfaces.

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
