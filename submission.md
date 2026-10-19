# Project Submission: BugSlayerX

## 1. Project Overview
- **Project Name:** BugSlayerX (Autonomous Bug Bounty & Exploit Verifier)
- **Track:** Subjective Consensus / AI Governance / Smart Contract Security Infrastructure
- **Network:** GenLayer studionet (Chain ID: `61999` / `0xF1EF`)
- **Deployed Contract Address:** `0xe36309cc5f7f95a69d0D80FE1D029B706CfFDcd4`
- **Deployment Transaction Hash:** `0xf6bded7d9e43dbd06996302f84d1ef768df92febdbc93c5ab6522451b2514059`
- **RPC URL:** `https://studio.genlayer.com/api`

---

## 2. The 1-Line Pitch
> *"Traditional blockchains cannot access GitHub diffs, scrape external exploit PoCs, or assess subjective vulnerability severity; without GenLayer's on-chain web rendering (`gl.nondet.web.render`) and LLM validator jury consensus (`gl.vm.run_nondet`), an autonomous, decentralized bug bounty verification and payout protocol is fundamentally impossible."*

---

## 3. Key Accomplishments
1. **Full GenLayer Intelligent Contract Implementation:** Written in GenVM Python (`contracts/bug_slayer_x.py`), following all non-deterministic storage and equivalence rules in `exlorer/`.
2. **Robust Consensus Architecture:** Implemented `gl.vm.run_nondet` with custom semantic validator logic that enforces strict consensus on qualitative severity verdicts (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INVALID`, `FAILED_EVIDENCE`) and score tolerance bounds ($\le 20$ points delta), while allowing textual diversity in triage summary reports.
3. **SSRF and Edge Case Defense:** Strict validation of PoC URLs against localhost/private IP subnets and automatic 100% refund of requested bounty deposits on 404/inaccessible evidence sources.
4. **Verified Live Deployment:** Successfully deployed and verified on GenLayer Studionet with `status: 5` (FINALIZED) and `result: 6` (SUCCESS).
5. **Comprehensive Test Suite:** 10 out of 10 automated unit tests passing via `pytest tests -v` with simulator mocks for all consensus branches.
