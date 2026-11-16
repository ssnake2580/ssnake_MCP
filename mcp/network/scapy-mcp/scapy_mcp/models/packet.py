"""PacketSpec — an ordered stack of layer specs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# NOTE: `LayerSpec` must stay a runtime import. Ruff's TC001 wants it inside a
# `TYPE_CHECKING` block, but pydantic resolves field annotations at runtime to
# build the validator. Under `TYPE_CHECKING` the model silently becomes
# incomplete (`__pydantic_complete__ is False`) and every `model_validate` call
# raises `PydanticUserError: ... is not fully defined`.
from scapy_mcp.models.layers import LayerSpec  # noqa: TC001


class PacketSpec(BaseModel):
    """Packet built bottom-up: layers[0] is the wire-most, layers[-1] is payload."""

    model_config = ConfigDict(extra="forbid")
    layers: list[LayerSpec]
