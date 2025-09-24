"""Entrypoint for the ZKAT Milestone 1 agent.

This module will orchestrate the Milestone 1 workflow:
    * Run Nmap against the configured target.
    * Canonicalize the Nmap XML output.
    * Compute the SHA3-256 digest of the canonical projection.
    * Produce the attestation payload and sign it with Dilithium2.
    * Append email and Git anchoring metadata.
    * Persist outputs to the run directory and update chain state.

Implementation will follow the plan documented in README.md.
"""

from __future__ import annotations


def main() -> None:
    """Placeholder CLI entrypoint for the milestone agent."""
    raise NotImplementedError("Milestone 1 agent workflow not yet implemented")


if __name__ == "__main__":
    main()
