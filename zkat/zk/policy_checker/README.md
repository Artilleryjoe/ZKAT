# zkVM policy checker (guest)

This folder hosts the zkVM guest program that evaluates the `no_smb_exposed`
policy. The guest takes the canonical input format documented in
`docs/zk_design.md` and emits only a boolean policy result plus the canonical
input commitment.

The current repository contains placeholder source files to keep the interface
stable while the zkVM implementation is finalized.
