import pytest
import json
from gltest import *
from conftest import sim_installMocks


@pytest.fixture
def contract(direct_deploy):
    return direct_deploy("contracts/bug_slayer_x.py")


def test_initial_state(contract, direct_vm, direct_alice, direct_bob):
    assert contract.get_report_count() == 0
    owner_str = contract.get_owner().lower()
    expected_sender = direct_vm.sender.hex().lower() if isinstance(direct_vm.sender, bytes) else str(direct_vm.sender).lower()
    if not expected_sender.startswith("0x"):
        expected_sender = "0x" + expected_sender
    assert owner_str == expected_sender

    stats = json.loads(contract.get_stats())
    assert stats["total_reports"] == 0
    assert stats["verified_count"] == 0
    assert stats["total_bounty_paid"] == "0"


def test_submit_bug_report_success(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 5000

    rid = contract.submit_bug_report(
        vulnerability_title="Critical Reentrancy in Lending Vault Liquidation Logic",
        description="The liquidateBorrow function burns debt tokens before updating collaterals, enabling recursive flash-loan drain.",
        poc_url="https://github.com/defi-protocol/contracts/commit/a1b2c3d4e5f67890123456789abcdef012345678"
    )

    assert rid == "1"
    assert contract.get_report_count() == 1

    rep = json.loads(contract.get_report("1"))
    assert rep["report_id"] == "1"
    assert rep["researcher"] == direct_alice.as_hex.lower()
    assert "Critical Reentrancy" in rep["vulnerability_title"]
    assert rep["bounty_requested"] == "5000"
    assert rep["status"] == "PENDING"
    assert rep["severity"] == "PENDING"
    assert rep["score"] == 0

    stats = json.loads(contract.get_stats())
    assert stats["total_reports"] == 1


def test_submit_bug_report_validations(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 1000

    # 1. Short title (< 5 chars)
    with pytest.raises(Exception, match="Vulnerability title is too short"):
        contract.submit_bug_report(
            vulnerability_title="Bug",
            description="Valid description with more than twenty characters long.",
            poc_url="https://github.com/project/core/commit/abc"
        )

    # 2. Short description (< 20 chars)
    with pytest.raises(Exception, match="Description is too short"):
        contract.submit_bug_report(
            vulnerability_title="Valid Vulnerability Title",
            description="Too short",
            poc_url="https://github.com/project/core/commit/abc"
        )

    # 3. Invalid URL scheme
    with pytest.raises(Exception, match="URL must start with http:// or https://"):
        contract.submit_bug_report(
            vulnerability_title="Valid Vulnerability Title",
            description="Valid description with more than twenty characters long.",
            poc_url="ftp://exploit.sh/poc.py"
        )

    # 4. SSRF / Localhost attempt
    with pytest.raises(Exception, match="Local and private network URLs are prohibited"):
        contract.submit_bug_report(
            vulnerability_title="Valid Vulnerability Title",
            description="Valid description with more than twenty characters long.",
            poc_url="http://127.0.0.1:8000/exploit"
        )


def test_verify_vulnerability_not_found(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    with pytest.raises(Exception, match="Bug report not found"):
        contract.verify_vulnerability("999")


def test_verify_vulnerability_critical_success(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 5000

    rid = contract.submit_bug_report(
        vulnerability_title="Critical Reentrancy in Lending Vault Liquidation Logic",
        description="The liquidateBorrow function burns debt tokens before updating collaterals, enabling recursive flash-loan drain.",
        poc_url="https://github.com/defi-protocol/contracts/commit/a1b2c3d4e5f67890123456789abcdef012345678"
    )

    poc_diff = """
    diff --git a/contracts/Vault.sol b/contracts/Vault.sol
    index 1234567..89abcdef 100644
    --- a/contracts/Vault.sol
    +++ b/contracts/Vault.sol
    @@ -120,6 +120,7 @@ contract Vault is ReentrancyGuard {
             uint256 collat = calculateCollateral(borrower);
    +        _updateBalance(borrower, 0);
             payable(msg.sender).transfer(collat);
    -        _updateBalance(borrower, 0);
         }
    """

    sim_installMocks({
        "web_mocks": {
            ".*github.com.*": {"status": 200, "body": poc_diff}
        },
        "llm_mocks": {
            "score": 95,
            "severity": "CRITICAL",
            "evaluation_report": "Verified severe reentrancy drain bug before state update. PoC diff is clear and exploit reproduction succeeds."
        }
    }, vm=direct_vm)

    contract.verify_vulnerability(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "VERIFIED"
    assert rep["severity"] == "CRITICAL"
    assert rep["score"] == 95
    assert rep["payout"] == "5000"
    assert "Verified severe reentrancy" in rep["evaluation_report"]

    stats = json.loads(contract.get_stats())
    assert stats["verified_count"] == 1
    assert stats["total_bounty_paid"] == "5000"


def test_verify_vulnerability_invalid_rejected(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 3000

    rid = contract.submit_bug_report(
        vulnerability_title="False Positive Overflow in Solidity 0.8+",
        description="Claiming safe addition in 0.8+ causes overflow exploit without custom unchecked blocks.",
        poc_url="https://github.com/defi-protocol/contracts/commit/invalid123"
    )

    poc_diff = """
    diff --git a/contracts/Token.sol b/contracts/Token.sol
    --- a/contracts/Token.sol
    +++ b/contracts/Token.sol
    @@ -10,3 +10,3 @@
    -    uint256 c = a + b;
    +    uint256 c = a + b; // no change
    """

    sim_installMocks({
        "web_mocks": {
            ".*github.com.*": {"status": 200, "body": poc_diff}
        },
        "llm_mocks": {
            "score": 5,
            "severity": "INVALID",
            "evaluation_report": "False positive report. Solidity 0.8+ has built-in overflow checks. No vulnerability exists."
        }
    }, vm=direct_vm)

    contract.verify_vulnerability(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "REJECTED"
    assert rep["severity"] == "INVALID"
    assert rep["payout"] == "0"
    assert "False positive" in rep["evaluation_report"]

    stats = json.loads(contract.get_stats())
    assert stats["verified_count"] == 0
    assert stats["total_bounty_paid"] == "0"


def test_verify_vulnerability_failed_evidence_refund(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 2500

    rid = contract.submit_bug_report(
        vulnerability_title="Flash Loan Oracle Arbitrage Vulnerability",
        description="Manipulating spot pool reserves to trigger bad liquidations across paired lending pools.",
        poc_url="https://github.com/defi-protocol/contracts/commit/broken404"
    )

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 404, "body": "404 Not Found - Repository or commit does not exist."}
        }
    }, vm=direct_vm)

    contract.verify_vulnerability(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "FAILED_EVIDENCE"
    assert rep["severity"] == "FAILED_EVIDENCE"
    assert rep["payout"] == "2500"
    assert "offline or inaccessible" in rep["evaluation_report"]

    stats = json.loads(contract.get_stats())
    assert stats["verified_count"] == 0
    assert stats["total_bounty_paid"] == "0"


def test_cannot_reverify_verified_report(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 2000

    rid = contract.submit_bug_report(
        vulnerability_title="Access Control Missing in Emergency Pause",
        description="Anyone can call emergencyPause without admin role modifier check.",
        poc_url="https://github.com/defi-protocol/contracts/commit/access1"
    )

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": "diff --git a/Admin.sol b/Admin.sol"}
        },
        "llm_mocks": {
            "score": 80,
            "severity": "HIGH",
            "evaluation_report": "High severity missing access control."
        }
    }, vm=direct_vm)

    contract.verify_vulnerability(rid)

    with pytest.raises(Exception, match="Bug report has already been verified"):
        contract.verify_vulnerability(rid)


def test_cancel_report_by_researcher(contract, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 1500

    rid = contract.submit_bug_report(
        vulnerability_title="Unused Variable in Helper Contract Library",
        description="Minor unused variable gas optimization report mistakenly submitted as vulnerability.",
        poc_url="https://github.com/defi-protocol/contracts/commit/cancel1"
    )

    contract.cancel_report(rid)

    rep = json.loads(contract.get_report(rid))
    assert rep["status"] == "CANCELLED"
    assert rep["severity"] == "CANCELLED"
    assert rep["payout"] == "1500"
    assert "Cancelled by researcher" in rep["evaluation_report"]

    with pytest.raises(Exception, match="Only pending reports can be cancelled"):
        contract.cancel_report(rid)


def test_cancel_report_unauthorized(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    direct_vm.value = 1000

    rid = contract.submit_bug_report(
        vulnerability_title="Reentrancy in Staking Rewards Claim Function",
        description="External call to user before decrementing pending reward tally state.",
        poc_url="https://github.com/defi-protocol/contracts/commit/reentrancy2"
    )

    # Bob tries to cancel Alice's report
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="Only researcher can cancel report"):
        contract.cancel_report(rid)
