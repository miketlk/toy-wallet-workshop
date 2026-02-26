"""Reusable toy wallet client package for tests and labs."""

from .toy_wallet_usb import (
    PortDiscoveryError,
    ProtocolError,
    ProtocolResponse,
    ToyWalletCDCClient,
    UI_STATE_BOOT_HEX,
    UI_STATE_ERROR_HEX,
    UI_STATE_LOCKED_HEX,
    UI_STATE_ONBOARDING_HEX,
    UI_STATE_PIN_ENTRY_HEX,
    UI_STATE_UNLOCKED_HEX,
    WalletUIState,
    discover_protocol_port,
)

__all__ = [
    "PortDiscoveryError",
    "ProtocolError",
    "ProtocolResponse",
    "ToyWalletCDCClient",
    "WalletUIState",
    "UI_STATE_BOOT_HEX",
    "UI_STATE_LOCKED_HEX",
    "UI_STATE_PIN_ENTRY_HEX",
    "UI_STATE_UNLOCKED_HEX",
    "UI_STATE_ONBOARDING_HEX",
    "UI_STATE_ERROR_HEX",
    "discover_protocol_port",
]
