"""Cred OpenAI Agents SDK integration."""

from .tool import cred_delegate_tool, cred_use_tool

CredTool = cred_delegate_tool

__all__ = ["cred_delegate_tool", "cred_use_tool", "CredTool"]
