"""Host engine v1 (`host.windows`) building blocks. See docs/design/host-engine-v1.md.

Everything here reads EVTX files the user exported from their own PC, in place, and never
contacts any address. Event content lives only in memory during an import.
"""
