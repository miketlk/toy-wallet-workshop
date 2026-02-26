# Toy Wallet Python Client

Reusable Python client for talking to the toy wallet CDC protocol over USB serial.
Use this from `tests/` and future `labs/`.

## Module

- Import path: `from client import ...`
- Implementation: `client/toy_wallet_usb.py`

## API

- `discover_protocol_port(vid, pid, interface_hint="Host Proto", interface_index_hint=2) -> str`
  Finds the most likely protocol CDC port for the device.
- `ToyWalletCDCClient(port, baudrate=115200, timeout=2.0)`
  Context-managed serial client.
- `ToyWalletCDCClient.request(opcode, arg_hex=None) -> ProtocolResponse`
  Sends validated protocol request (`opcode` or `opcode <hex>`).
- `ToyWalletCDCClient.command(line) -> ProtocolResponse`
  Sends a raw single-line command (no CR/LF allowed).
- `ProtocolResponse`
  Response object with fields:
  - `status: str` (`"ok"` or `"err"`)
  - `hex_arg: str | None`
  - `ok` property (`True` when status is `"ok"`)
- `PortDiscoveryError`
  Raised when auto-discovery cannot safely choose a single port.
- `ProtocolError`
  Raised when the firmware response format is malformed.

## Usage

Run Python from the repo root so `client/` is importable.

```bash
python3 -m pip install -r requirements.txt
```

### 1) Auto-discover port and ping

```python
from client import ToyWalletCDCClient, discover_protocol_port

port = discover_protocol_port(vid=0xCAFE, pid=0x4002)
with ToyWalletCDCClient(port=port, timeout=2.0) as wallet:
    resp = wallet.request("ping")
    print(resp.status, resp.ok, resp.hex_arg)  # ok True None
```

### 2) Use an explicit port

```python
from client import ToyWalletCDCClient

with ToyWalletCDCClient(port="/dev/ttyACM1") as wallet:
    resp = wallet.request("ping")
    if not resp.ok:
        raise RuntimeError("wallet returned err")
```

### 3) Raw command + payload response

```python
from client import ToyWalletCDCClient

with ToyWalletCDCClient(port="/dev/ttyACM1") as wallet:
    resp = wallet.command("getpub")
    if resp.ok and resp.hex_arg is not None:
        pubkey_bytes = bytes.fromhex(resp.hex_arg)
        print(len(pubkey_bytes))
```
