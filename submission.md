# Project Submission: BugSlayerX (DEPIV Protocol)

## 1. Project Overview
- **Project Name:** BugSlayerX: Differential Exploit & Invariant Verifier (DEPIV Protocol)
- **Track:** Subjective Consensus / AI Governance / Smart Contract Security Infrastructure
- **Network:** GenLayer studionet (Chain ID: `61999` / `0xF1EF`)
- **Deployed Contract Address:** `0xA673c8D97A45546A304A0Bf65c0133CA904f9a57`
- **Deployment Transaction Hash:** `0xc0f6f12c0a3c1b5cc10a4e2ad2cd2de014e13e9d0d65f7cc17359923d436bff4`
- **RPC URL:** `https://studio.genlayer.com/api`

---

## 2. The 1-Line Pitch
> *"Traditional blockchains cannot perform differential analysis between codebases and test scripts or enforce game-theoretic exploit verification; without GenLayer's multi-source on-chain web rendering (`gl.nondet.web.render`) and LLM jury consensus (`gl.vm.run_nondet`), an autonomous, spam-proof differential exploit and invariant verification protocol is fundamentally impossible."*

---

## 3. Key Accomplishments & Architectural Differentiation
1. **Dual-Evidence Cross-Verification:** Unlike generic bug bounty contracts that review a single submission link, BugSlayerX cross-references the target smart contract source code against an independent reproduction PoC script on-chain to verify whether a protocol state invariant is genuinely violated.
2. **Anti-Spam Bonding & Slashing Game Theory:** Researchers must stake a minimum `triage_bond` (50 GEN). Fabricated or spam submissions forfeit 100% of their bond to the protocol treasury, eliminating triage congestion. Verified exploits refund the bond and award dynamic bounty payouts.
3. **On-Chain Vulnerability Fingerprint Registry:** Deterministically records vulnerability root-cause fingerprints on-chain to prevent duplicate submissions, exploit front-running, and plagiarism.
4. **Multi-Pillar Semantic Consensus:** Enforces strict validator agreement across three technical pillars (`is_invariant_broken`, formal CWE classification, and risk tier: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SPAM`) alongside numerical impact score tolerances ($\le 20$ delta).
5. **Verified Live Deployment & Full Test Suite:** Deployed on GenLayer Studionet (`0xA673c8D97A45546A304A0Bf65c0133CA904f9a57`) with 11/11 automated unit tests passing via `pytest tests -v`.
