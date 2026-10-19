# BugSlayerX: Autonomous Bug Bounty & Exploit Verifier Protocol

[![GenLayer Studionet](https://img.shields.io/badge/GenLayer-Studionet-purple.svg)](https://studio.genlayer.com)
[![GenVM Contract](https://img.shields.io/badge/GenVM-Python%20v0.2.16-blue.svg)](https://docs.genlayer.com)
[![Build Status](https://img.shields.io/badge/Tests-10%2F10%20Passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

BugSlayerX is a decentralized, autonomous bug bounty triage and exploit verification protocol natively built on **GenLayer**. It eliminates manual bottlenecking in smart contract security reviews by utilizing GenLayer's decentralized AI validator jury and on-chain web scraping to verify vulnerability Proof-of-Concepts (PoCs) and instantly trigger bounty disbursements.

---

## 🚀 Live Studionet Deployment

- **Network:** GenLayer Studionet (`studionet`)
- **Chain ID:** `61999` (`0xF1EF`)
- **RPC Endpoint:** `https://studio.genlayer.com/api`
- **Contract Address:** `0xe36309cc5f7f95a69d0D80FE1D029B706CfFDcd4`
- **Deployment Transaction Hash:** `0xf6bded7d9e43dbd06996302f84d1ef768df92febdbc93c5ab6522451b2514059`
- **Finality Status:** `Status: 5 (FINALIZED)` | `Result: 6 (SUCCESS)`

---

## 🎯 The Core Problem & GenLayer Fit

### The Problem
In Web3 and smart contract security:
1. **Manual Triage Delays:** Core teams and protocol maintainers spend hundreds of hours filtering duplicate, spam, or false-positive reports submitted to bug bounty platforms.
2. **Centralized Arbiters:** Centralized bug bounty platforms can arbitrarily dismiss valid zero-day findings or delay payouts.
3. **Information Asymmetry & Trust Deficit:** White-hat hackers must trust that protocols won't silently patch reported vulnerabilities without paying out fair bounties.

### Why BugSlayerX CANNOT Exist on Traditional Blockchains
- **Solidity / EVM Limitations:** Ethereum or Solana cannot fetch web content (e.g. GitHub commits, pull requests, raw exploit scripts) without centralized oracles. Moreover, deterministic smart contracts cannot parse unstructured code diffs or evaluate exploit severity.
- **The GenLayer Solution:**
  - **On-chain Web Scraping (`gl.nondet.web.render`):** GenLayer validators directly fetch and parse external vulnerability PoCs and code commits.
  - **Decentralized LLM Consensus (`gl.vm.run_nondet`):** A multi-validator AI jury independently evaluates vulnerability impact, determines severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INVALID`), and reaches consensus on the verdict and score.
  - **Automated Settlement:** If verified, bounties are immediately disbursed to the researcher on-chain.

---

## 🏛 Architecture & Consensus Mechanism

```
+-----------------------------------------------------------------------------------+
|                                White-hat Researcher                               |
+-----------------------------------------------------------------------------------+
                                         |
                                         | submit_bug_report(title, desc, poc_url)
                                         v
+-----------------------------------------------------------------------------------+
|                        BugSlayerX Intelligent Contract                            |
|             (0xe36309cc5f7f95a69d0D80FE1D029B706CfFDcd4)                         |
+-----------------------------------------------------------------------------------+
                                         |
                                         | verify_vulnerability(report_id)
                                         v
+-----------------------------------------------------------------------------------+
|                         GenLayer Decentralized AI Jury                            |
|                                                                                   |
|  [Leader Node]                                                                    |
|    - gl.nondet.web.render(poc_url) -> Scrapes commit diff / PoC script            |
|    - gl.nondet.exec_prompt(...) -> Evaluates severity, score (0-100), report      |
|                                                                                   |
|  [Validator Nodes]                                                                |
|    - Independently render PoC URL & run security evaluation                       |
|    - Semantic Validation: Ensures severity verdict MATCHES exactly                |
|    - Numerical Tolerance: Asserts score delta <= 20 points                         |
|    - Allows phrasing variations in natural language triage report                 |
+-----------------------------------------------------------------------------------+
                                         |
                  +----------------------+----------------------+
                  |                                             |
                  v                                             v
        [Status: VERIFIED]                            [Status: REJECTED]
  - Severity: CRITICAL/HIGH/MED/LOW             - Severity: INVALID
  - Instant Bounty Disbursed                    - No payout
  - Stats updated                               - Retained as audit record
```

### Equivalence Principle Implementation
BugSlayerX uses `gl.vm.run_nondet` with a custom `validator_fn`:
```python
def validator_fn(leader_res) -> bool:
    if not isinstance(leader_res, gl.vm.Return):
        return False
    leader = leader_res.calldata

    # Strict semantic check on severity verdict
    mine = leader_fn()
    if mine.get("severity") != leader.get("severity"):
        return False

    # Score tolerance bound (<= 20 points)
    if leader.get("severity") != "FAILED_EVIDENCE":
        if abs(int(leader.get("score", 0)) - int(mine.get("score", 0))) > 20:
            return False

    return True
```

---

## 🔒 Security & Edge Case Defenses

1. **Anti-SSRF Protection:** Strict sanitization blocking private IPs (`localhost`, `127.0.0.1`, `10.*`, `192.168.*`, `172.16.*`, `169.254.*`).
2. **Broken / Offline Evidence Fallback:** If a PoC link returns 404 or fails to render, the contract transitions to `FAILED_EVIDENCE` and automatically refunds any locked bounty deposit.
3. **No Re-entrancy / Double-verification:** Reports can only be verified once from `PENDING` state.
4. **Researcher Cancellation:** Researchers can voluntarily cancel pending reports and reclaim requested funds prior to verification.

---

## 🧪 Testing & Verification

BugSlayerX includes a full unit test suite with 10 comprehensive tests using `gltest`:

```bash
pytest tests -v
```

### Test Coverage Results:
- `test_initial_state`: Verifies contract owner, report count, and statistics.
- `test_submit_bug_report_success`: Validates report submission and state recording.
- `test_submit_bug_report_validations`: Tests minimum length constraints, URL schemes, and SSRF filtering.
- `test_verify_vulnerability_not_found`: Checks non-existent report exception handling.
- `test_verify_vulnerability_critical_success`: Verifies critical exploit consensus and instant payout.
- `test_verify_vulnerability_invalid_rejected`: Tests rejection of false positives.
- `test_verify_vulnerability_failed_evidence_refund`: Tests automatic refund on 404/broken evidence.
- `test_cannot_reverify_verified_report`: Prevents replay / duplicate verification.
- `test_cancel_report_by_researcher`: Tests cancellation and deposit reclaim.
- `test_cancel_report_unauthorized`: Prohibits unauthorized cancellation by third parties.

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
