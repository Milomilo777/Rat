#!/bin/bash
# Reviewing logic based on requirements

# R1: a removed rule shrinks the pf blocklist.
# R2: an app with a rule never prompts.
# R3: alerts time out to the configured default.
# R4: imported rules arrive disabled and unapproved.
# R5: state is written atomically and survives a crash mid-write.
# R6: a malformed state file does not wipe user rules.
# R7: the update checker never runs code it downloads.
# R8: timers and observers do not leak on window close.
# R9: no data race on shared state between the sampler and the UI.
