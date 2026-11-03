# BugSlayerX: Differential Exploit & Invariant Verifier (DEPIV Protocol)

[![GenLayer Studionet](https://img.shields.io/badge/GenLayer-Studionet-purple.svg)](https://studio.genlayer.com)
[![GenVM Contract](https://img.shields.io/badge/GenVM-Python%20v0.2.16-blue.svg)](https://docs.genlayer.com)
[![Build Status](https://img.shields.io/badge/Tests-11%2F11%20Passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

BugSlayerX is a decentralized, game-theoretic security verification primitive natively built on **GenLayer**. Moving beyond naive single-URL bug report courts, BugSlayerX introduces the **Differential Exploit & Invariant Verifier (DEPIV Protocol)**: performing multi-source differential code analysis between target contract source code and independent exploit reproduction test scripts directly on-chain, paired with anti-spam staking and vulnerability fingerprinting.

---

## 🚀 Live Studionet Deployment

- **Network:** GenLayer Studionet (`studionet`)
- **Chain ID:** `61999` (`0xF1EF`)
- **RPC Endpoint:** `https://studio.genlayer.com/api`
- **Contract Address:** `0xA673c8D97A45546A304A0Bf65c0133CA904f9a57`
- **Deployment Transaction Hash:** `0xc0f6f12c0a3c1b5cc10a4e2ad2cd2de014e13e9d0d65f7cc17359923d436bff4`
- **Finality Status:** `Status: 5 (FINALIZED)` | `Result: 6 (SUCCESS)`

---

## 🎯 The Core Problem & GenLayer Fit

### The Problem
1. **Triage Sybil & False-Positive Spam:** Web3 bug bounty programs are inundated with unverified AI-hallucinated reports or benign warnings that waste protocol resources.
2. **Exploit Front-Running & Plagiarism:** On-chain reporting without cryptographic state registration enables malicious actors to copy and front-run honest white-hat researchers.
3. **Single-Source Information Deficit:** Traditional bug bounty contracts only look at a single arbitrary URL without verifying whether a PoC actually triggers an invariant breach against the real contract code.

### Why BugSlayerX CANNOT Exist on Traditional Blockchains
- **Solidity / EVM Limitations:** Ethereum cannot fetch two independent external repositories on-chain without centralized oracles. Deterministic smart contracts cannot execute differential code analysis or reason about semantic state invariants.
- **The GenLayer Solution:**
  - **Multi-Source Web Scraping (`gl.nondet.web.render`):** GenLayer validators simultaneously fetch both the Target Contract Source and the Reproduction PoC Script on-chain.
  - **Differential Analysis & Semantic Consensus (`gl.vm.run_nondet`):** A decentralized LLM jury verifies whether the invariant is breached, categorizes the bug under formal CWE taxonomies, and converges on risk tiers and impact scores.
  - **Game-Theoretic Bonding & Slashing:** Spammers lose their staked `triage_bond` to the protocol treasury, while valid researchers receive full bond refunds plus dynamic bounty rewards.

---

## 🏛 Architecture & Consensus Flow

```
+-----------------------------------------------------------------------------------+
|                                White-hat Researcher                               |
+-----------------------------------------------------------------------------------+
                                         |
                                         | submit_exploit_report()
                                         | [Target URL + PoC URL + Bond Stake + Fingerprint]
                                         v
+-----------------------------------------------------------------------------------+
|                   BugSlayerX (DEPIV Intelligent Contract)                         |
|             (0xA673c8D97A45546A304A0Bf65c0133CA904f9a57)                         |
+-----------------------------------------------------------------------------------+
                                         |
                                         | verify_exploit(report_id)
                                         v
+-----------------------------------------------------------------------------------+
|                         GenLayer Decentralized AI Jury                            |
|                                                                                   |
|  [Leader Node]                                                                    |
|    - gl.nondet.web.render(target_contract_url) -> Scrapes vulnerable contract code |
|    - gl.nondet.web.render(reproduction_poc_url) -> Scrapes exploit PoC test script|
|    - gl.nondet.exec_prompt(...) -> Performs differential invariant analysis       |
|                                                                                   |
|  [Validator Nodes]                                                                |
|    - Independently cross-verify both sources and re-run differential audit        |
|    - Semantic Validation 1: is_invariant_broken MUST match                       |
|    - Semantic Validation 2: risk_tier (CRITICAL/HIGH/MED/LOW/SPAM) MUST match     |
|    - Semantic Validation 3: confirmed_cwe taxonomy classification MUST match      |
|    - Numerical Tolerance: impact_score delta <= 20 points                         |
+-----------------------------------------------------------------------------------+
                                         |
                  +----------------------+----------------------+
                  |                                             |
                  v                                             v
        [Status: VERIFIED]                           [Status: SLASHED_SPAM]
  - Invariant confirmed breached               - Invariant intact / false positive
  - Bond 100% refunded + Bounty paid           - 100% Bond slashed to Treasury
  - Fingerprint registered on-chain            - Zero payout
```

---

## 🔒 Security & Game Theory Defenses

1. **Anti-Spam Staking Bond:** A minimum stake of 50 GEN is required per submission. If determined to be spam, false positive, or fabricated, the bond is forfeited into `treasury_balance`.
2. **Deterministic Fingerprint Registry:** The root-cause fingerprint is indexed in `vulnerability_registry`. Any subsequent attempt to re-submit an existing vulnerability is rejected on-chain as a duplicate.
3. **Dual-URL Anti-SSRF:** Private IP ranges (`127.0.0.1`, `localhost`, `10.*`, `192.168.*`, `172.16.*`, `169.254.*`) are strictly prohibited.
4. **404 / Broken Evidence Safety:** If either source is offline or returns 404, the report is marked as `FAILED_EVIDENCE` and the researcher's bond is 100% refunded without penalty.

---

## 🧪 Testing & Verification

BugSlayerX includes a unit test suite with 11 comprehensive tests using `gltest`:

```bash
pytest tests -v
```

### Test Coverage Results:
- `test_initial_state`: Verifies contract ownership, min triage bond (50 GEN), and initial metrics.
- `test_fund_bounty_pool`: Tests protocol sponsors depositing funds into the bounty treasury.
- `test_submit_exploit_report_success`: Validates dual-source submission, bonding, and state tracking.
- `test_submit_exploit_report_validations`: Tests minimum bond, short titles, identical URLs, and SSRF filtering.
- `test_verify_exploit_critical_dual_source_success`: Tests dual-source differential analysis, invariant breach verification, and dynamic reward disburse.
- `test_duplicate_exploit_frontrunning_rejection`: Asserts on-chain duplicate fingerprint prevention.
- `test_verify_exploit_spam_bond_slashed`: Verifies bond slashing into treasury when an exploit is invalid/spam.
- `test_verify_exploit_failed_evidence_refund`: Tests automatic bond refund on 404/broken evidence.
- `test_cancel_pending_report_by_researcher`: Tests cancellation and bond reclaim.
- `test_cancel_report_unauthorized`: Prohibits unauthorized cancellation by third parties.
- `test_cannot_reverify_resolved_report`: Prevents replay / duplicate verification.

---

## 🛠 Local Setup & Development

### Prerequisites
- Python 3.11+
- `pip install -r requirements-dev.txt`

### Running Tests
```bash
pytest tests -v
```

### Deploying to Studionet
```bash
python scripts/deploy_studionet.py
```
