import pytest
import json
from gltest import *
from conftest import sim_installMocks


@pytest.fixture
def contract(direct_deploy):
    return direct_deploy("contracts/bug_slayer_x.py")


def test_initial_state(contract, direct_vm, direct_alice, direct_bob):
    assert contract.get_report_count() == 0
    assert contract.get_min_triage_bond() == "50"
    owner_str = contract.get_owner().lower()
    expected_sender = direct_vm.sender.hex().lower() if isinstance(direct_vm.sender, bytes) else str(direct_vm.sender).lower()
    if not expected_sender.startswith("0x"):
        expected_sender = "0x" + expected_sender
    assert owner_str == expected_sender

    stats = json.loads(contract.get_stats())
    assert stats["total_reports"] == 0
    assert stats["verified_count"] == 0
    assert stats["slashed_spam_count"] == 0
    assert stats["treasury_balance"] == "0"
    assert stats["total_bounty_paid"] == "0"


def test_fund_bounty_pool(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 5000

    contract.fund_bounty_pool()
    stats = json.loads(contract.get_stats())
    assert stats["treasury_balance"] == "5000"


def test_submit_exploit_report_success(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 100

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/defi-protocol/lending/blob/main/Vault.sol",
        reproduction_poc_url="https://github.com/whitehat/exploits/blob/main/test_reentrancy_drain.py",
        cwe_tag="CWE-841",
        vulnerability_title="State-Update Reentrancy Drain in Liquidation Engine",
        invariant_description="Vault collateral total must never decrease without proportional debt liquidation.",
        fingerprint="fp_reentrancy_vault_liquidate_001"
    )

    assert rid == "1"
    assert contract.get_report_count() == 1

    rep = json.loads(contract.get_report("1"))
    assert rep["report_id"] == "1"
    assert rep["researcher"] == direct_alice.as_hex.lower()
    assert rep["triage_bond"] == "100"
    assert rep["status"] == "PENDING"
    assert rep["cwe_tag"] == "CWE-841"
    assert rep["is_invariant_broken"] is False
    assert rep["fingerprint"] == "fp_reentrancy_vault_liquidate_001"


def test_submit_exploit_report_validations(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice

    # 1. Insufficient triage bond (< 50 GEN)
    direct_vm.value = 40
    with pytest.raises(Exception, match="Insufficient triage bond"):
        contract.submit_exploit_report(
            target_contract_url="https://github.com/project/core/Vault.sol",
            reproduction_poc_url="https://github.com/whitehat/tests/poc.py",
            cwe_tag="CWE-284",
            vulnerability_title="Valid Title For Report",
            invariant_description="Invariant description with more than twenty characters long.",
            fingerprint="fp_valid_test_001"
        )

    direct_vm.value = 100

    # 2. Short title (< 5 chars)
    with pytest.raises(Exception, match="Vulnerability title is too short"):
        contract.submit_exploit_report(
            target_contract_url="https://github.com/project/core/Vault.sol",
            reproduction_poc_url="https://github.com/whitehat/tests/poc.py",
            cwe_tag="CWE-284",
            vulnerability_title="Bug",
            invariant_description="Invariant description with more than twenty characters long.",
            fingerprint="fp_valid_test_001"
        )

    # 3. Short invariant (< 20 chars)
    with pytest.raises(Exception, match="Invariant description must be at least 20 characters"):
        contract.submit_exploit_report(
            target_contract_url="https://github.com/project/core/Vault.sol",
            reproduction_poc_url="https://github.com/whitehat/tests/poc.py",
            cwe_tag="CWE-284",
            vulnerability_title="Valid Title For Report",
            invariant_description="Too short",
            fingerprint="fp_valid_test_001"
        )

    # 4. Same URL for both target and PoC
    with pytest.raises(Exception, match="Target source and reproduction PoC must be distinct URLs"):
        contract.submit_exploit_report(
            target_contract_url="https://github.com/project/core/Vault.sol",
            reproduction_poc_url="https://github.com/project/core/Vault.sol",
            cwe_tag="CWE-284",
            vulnerability_title="Valid Title For Report",
            invariant_description="Invariant description with more than twenty characters long.",
            fingerprint="fp_valid_test_001"
        )

    # 5. Localhost / SSRF attack attempt
    with pytest.raises(Exception, match="Local and private network URLs are prohibited"):
        contract.submit_exploit_report(
            target_contract_url="http://127.0.0.1:8080/internal.sol",
            reproduction_poc_url="https://github.com/whitehat/tests/poc.py",
            cwe_tag="CWE-284",
            vulnerability_title="Valid Title For Report",
            invariant_description="Invariant description with more than twenty characters long.",
            fingerprint="fp_valid_test_001"
        )


def test_verify_exploit_critical_dual_source_success(contract, direct_vm, direct_alice, direct_bob):
    # 1. Bob funds the treasury pool
    direct_vm.sender = direct_bob
    direct_vm.value = 10000
    contract.fund_bounty_pool()

    # 2. Alice submits a valid exploit
    direct_vm.sender = direct_alice
    direct_vm.value = 100

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/lending/contracts/Vault.sol",
        reproduction_poc_url="https://github.com/whitehat/tests/test_reentrancy_poc.py",
        cwe_tag="CWE-841",
        vulnerability_title="Critical Reentrancy Drain in Liquidation Routine",
        invariant_description="Collateral balances cannot be withdrawn without proportional burned debt.",
        fingerprint="fp_critical_reentrancy_vault_99"
    )

    sim_installMocks({
        "web_mocks": {
            ".*Vault.sol.*": {"status": 200, "body": "function liquidate() external { payable(msg.sender).call(value); balances[user] = 0; }"},
            ".*test_reentrancy_poc.py.*": {"status": 200, "body": "def test_exploit_drain(): contract.liquidate(); assert contract.balance == 0"}
        },
        "llm_mocks": {
            "is_invariant_broken": True,
            "confirmed_cwe": "REENTRANCY",
            "risk_tier": "CRITICAL",
            "impact_score": 95,
            "evaluation_summary": "PoC triggers fatal reentrancy drain before state modification. Direct funds theft confirmed."
        }
    }, vm=direct_vm)

    contract.verify_exploit(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "VERIFIED"
    assert rep["is_invariant_broken"] is True
    assert rep["confirmed_cwe"] == "REENTRANCY"
    assert rep["risk_tier"] == "CRITICAL"
    assert rep["impact_score"] == 95
    assert rep["bond_refunded"] == "100"
    assert int(rep["payout"]) > 0

    # Vulnerability fingerprint recorded in registry
    assert contract.get_registered_exploit("fp_critical_reentrancy_vault_99") == rid

    stats = json.loads(contract.get_stats())
    assert stats["verified_count"] == 1
    assert int(stats["total_bounty_paid"]) > 0


def test_duplicate_exploit_frontrunning_rejection(contract, direct_vm, direct_alice, direct_bob):
    # 1. Alice submits and verifies an exploit with fingerprint
    direct_vm.sender = direct_alice
    direct_vm.value = 100

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/lending/contracts/Vault.sol",
        reproduction_poc_url="https://github.com/whitehat/tests/test_reentrancy_poc.py",
        cwe_tag="CWE-841",
        vulnerability_title="Critical Reentrancy Drain in Liquidation Routine",
        invariant_description="Collateral balances cannot be withdrawn without proportional burned debt.",
        fingerprint="fp_critical_reentrancy_vault_99"
    )

    sim_installMocks({
        "web_mocks": {
            ".*Vault.sol.*": {"status": 200, "body": "function liquidate() external { payable(msg.sender).call(value); }"},
            ".*test_reentrancy_poc.py.*": {"status": 200, "body": "def test_exploit_drain(): pass"}
        },
        "llm_mocks": {
            "is_invariant_broken": True,
            "confirmed_cwe": "REENTRANCY",
            "risk_tier": "CRITICAL",
            "impact_score": 90,
            "evaluation_summary": "Reentrancy invariant broken."
        }
    }, vm=direct_vm)

    contract.verify_exploit(rid)

    # 2. Bob attempts to submit the identical vulnerability fingerprint after it was verified
    direct_vm.sender = direct_bob
    direct_vm.value = 100

    with pytest.raises(Exception, match="Duplicate exploit detected"):
        contract.submit_exploit_report(
            target_contract_url="https://github.com/lending/contracts/Vault_v2.sol",
            reproduction_poc_url="https://github.com/attacker/tests/copied_poc.py",
            cwe_tag="CWE-841",
            vulnerability_title="Copied PoC Report",
            invariant_description="Collateral balances cannot be withdrawn without proportional burned debt.",
            fingerprint="fp_critical_reentrancy_vault_99"
        )


def test_verify_exploit_spam_bond_slashed(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 100

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/safe/contracts/SafeMath.sol",
        reproduction_poc_url="https://github.com/spammer/tests/fake_poc.py",
        cwe_tag="CWE-190",
        vulnerability_title="False Positive Arithmetic Overflow in SafeMath",
        invariant_description="Addition must revert on 256-bit overflow condition.",
        fingerprint="fp_spam_overflow_002"
    )

    sim_installMocks({
        "web_mocks": {
            ".*SafeMath.sol.*": {"status": 200, "body": "function add(uint a, uint b) internal pure returns (uint) { return a + b; }"},
            ".*fake_poc.py.*": {"status": 200, "body": "def test_fake(): pass # No exploit"}
        },
        "llm_mocks": {
            "is_invariant_broken": False,
            "confirmed_cwe": "SPAM_INVALID",
            "risk_tier": "SPAM",
            "impact_score": 0,
            "evaluation_summary": "Fabricated false-positive. Solidity 0.8+ natively reverts on overflow. No exploit demonstrated."
        }
    }, vm=direct_vm)

    contract.verify_exploit(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "SLASHED_SPAM"
    assert rep["is_invariant_broken"] is False
    assert rep["confirmed_cwe"] == "SPAM_INVALID"
    assert rep["risk_tier"] == "SPAM"
    assert rep["payout"] == "0"
    assert rep["bond_refunded"] == "0"

    # Bond slashed into treasury
    stats = json.loads(contract.get_stats())
    assert stats["slashed_spam_count"] == 1


def test_verify_exploit_failed_evidence_refund(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 80

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/project/broken_target.sol",
        reproduction_poc_url="https://github.com/project/missing_poc.py",
        cwe_tag="CWE-284",
        vulnerability_title="Broken Link Report Test",
        invariant_description="Testing offline 404 evidence source handling for triage bond safety.",
        fingerprint="fp_broken_evidence_003"
    )

    sim_installMocks({
        "web_mocks": {
            ".*broken_target.sol.*": {"status": 404, "body": "404 Not Found"}
        }
    }, vm=direct_vm)

    contract.verify_exploit(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "FAILED_EVIDENCE"
    assert rep["risk_tier"] == "FAILED_EVIDENCE"
    assert rep["bond_refunded"] == "80"
    assert rep["payout"] == "0"


def test_cancel_pending_report_by_researcher(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 60

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/protocol/Staking.sol",
        reproduction_poc_url="https://github.com/whitehat/poc_cancel.py",
        cwe_tag="CWE-710",
        vulnerability_title="Unused Variable Gas Optimization",
        invariant_description="Gas optimization mistake submitted in error by researcher.",
        fingerprint="fp_cancel_test_004"
    )

    contract.cancel_pending_report(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "CANCELLED"
    assert rep["bond_refunded"] == "60"

    # Cannot cancel again
    with pytest.raises(Exception, match="Only pending reports can be cancelled"):
        contract.cancel_pending_report(rid)


def test_cancel_report_unauthorized(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    direct_vm.value = 70

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/protocol/Governance.sol",
        reproduction_poc_url="https://github.com/whitehat/gov_poc.py",
        cwe_tag="CWE-284",
        vulnerability_title="Quorum Calculation Flaw in Voting Engine",
        invariant_description="Votes must not be counted twice for delegated voting accounts.",
        fingerprint="fp_gov_quorum_005"
    )

    # Bob tries to cancel Alice's report
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="Only the original researcher can cancel this report"):
        contract.cancel_pending_report(rid)


def test_cannot_reverify_resolved_report(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 50

    rid = contract.submit_exploit_report(
        target_contract_url="https://github.com/protocol/Token.sol",
        reproduction_poc_url="https://github.com/whitehat/token_poc.py",
        cwe_tag="CWE-284",
        vulnerability_title="Token Mint Access Control Flaw",
        invariant_description="Only minter role can call mint function to issue supply.",
        fingerprint="fp_mint_access_006"
    )

    contract.cancel_pending_report(rid)

    with pytest.raises(Exception, match="Report has already been resolved"):
        contract.verify_exploit(rid)
