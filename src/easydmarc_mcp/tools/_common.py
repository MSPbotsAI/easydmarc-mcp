from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No EasyDMARC credentials. Send the X-EasyDMARC-Client-Id and "
    "X-EasyDMARC-Client-Secret headers.",
    False,
)

CONFIRM_DESC = "Required — must be set to true to proceed."


def confirm_gate(confirm: bool):
    """Return an error envelope if a destructive call wasn't explicitly confirmed."""
    if not confirm:
        return error_envelope(
            "invalid_argument", "destructive operation requires confirm=true", False
        )
    return None
