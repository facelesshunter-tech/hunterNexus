# Program and target selection

Choosing what to test, and confirming it's actually in scope, is a human
judgment step — hunterNexus does not automate it. This is a reference
checklist, not something the tool enforces for you.

## Platforms

Beyond HackerOne and Bugcrowd: Synack, Zerocopter, HackenProof,
Detectify, Defend Iceland, BugBounty.jp, Cobalt, Yogosha, bug.sh,
Immunefi, Intigriti, YesWeHack.

## Before running hunterNexus against a program's scope

- Is this a VDP (no bounty, but still authorized) or a paid program?
- Does the scope use wildcard or catch-all language? Wildcard patterns
  can sweep in infrastructure that was never intended to be in scope —
  confirm what's actually authorized, not just what the pattern
  incidentally matches.
- Does the program's rules of engagement define success in concrete,
  objective terms (e.g. "access to privileged data," "provable
  disruption of service") rather than a vague checklist? A program with
  clearly-defined impact criteria is generally a better candidate for
  deep recon investment than one without.
- Confirm out-of-scope assets explicitly before running
  `hunternexus scan` with `--bruteforce`, `--permutation`, or `--github`
  against a wide target list — those stages actively generate and
  resolve candidate hostnames that may include infrastructure outside
  the program's scope.
- Check for any restrictions on automated tooling, scan rate, or
  specific techniques (e.g. no automated vulnerability scanners, no
  high-volume fuzzing) before enabling the more active stages
  (`--content-discovery`, `--api-discovery`, `--vuln-verify`).
