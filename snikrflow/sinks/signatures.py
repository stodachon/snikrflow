"""
SnikrFlow sink signature database.

This is the configurable list of security-sensitive function names,
grouped by category. Edit this file directly to add/remove signatures --
no code changes needed elsewhere. Categories are free-form strings; add
a new one by just introducing a new key.
"""

from __future__ import annotations

SINK_SIGNATURES: dict[str, list[str]] = {
    "memory": [
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "alloca",
    ],
    "process_execution": [
        "system", "popen", "execve", "execl", "execlp", "execv", "execvp",
    ],
    "filesystem": [
        "open", "openat", "fopen", "freopen", "unlink", "rename",
    ],
    "networking": [
        "connect", "send", "sendto", "recv", "recvfrom",
    ],
    "dynamic_loading": [
        "dlopen", "dlsym",
    ],
    "comparison": [
        # NOT "dangerous" in the memory-corruption/code-exec sense --
        # these don't get attacker-controlled data flowing into a
        # sensitive operation. They're flagged because in crackme/
        # license-check/anti-tamper style binaries, THIS is where the
        # actual pass/fail decision lives. Different research question
        # than the other categories, same practical value: "where do I
        # look first."
        "strcmp", "strncmp", "strcasecmp", "strncasecmp",
        "strstr", "memcmp",
    ],
}