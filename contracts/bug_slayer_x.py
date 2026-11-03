# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import json

try:
    gl.UserError = gl.vm.UserError
except Exception:
    pass


def _addr_str(addr: Address) -> str:
    """Safely format an Address instance into a lowercase hex string."""
    try:
        return addr.as_hex.lower()
    except Exception:
        return str(addr).lower()


def _get_sender() -> Address:
    """Safely resolve transaction sender across GenVM runtime environments."""
    try:
        if hasattr(gl, "message"):
            if hasattr(gl.message, "sender"):
                return gl.message.sender
            if hasattr(gl.message, "sender_address"):
                return gl.message.sender_address
    except Exception:
        pass
    try:
        if hasattr(gl, "message_raw") and isinstance(gl.message_raw, dict):
            s = gl.message_raw.get("from") or gl.message_raw.get("sender")
            if s:
                return Address(str(s))
    except Exception:
        pass
    raise gl.UserError("Cannot resolve sender address.")


def _safe_transfer(recipient: Address, amount: bigint) -> None:
    """Safely transfer native GEN tokens."""
    if amount <= bigint(0):
        return
    gl.get_contract_at(recipient).emit_transfer(value=u256(int(amount)))


def _validate_url(raw_url: str) -> str:
    """Validate URL scheme and block private/SSRF IP addresses."""
    clean = raw_url.strip()
    if not (clean.startswith("http://") or clean.startswith("https://")):
        raise gl.UserError("URL must start with http:// or https://")
    clean_lower = clean.lower()
    for blocked in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "192.168.", "10.", "172.16.", "169.254."):
        if blocked in clean_lower:
            raise gl.UserError("Local and private network URLs are prohibited.")
    return clean


@allow_storage
@dataclass
class ExploitReport:
    report_id: str
    researcher: Address
    target_contract_url: str     # Source code/commit of the vulnerable contract
    reproduction_poc_url: str    # Independent test script/PoC reproducing the exploit
    cwe_tag: str                 # Claimed CWE vulnerability taxonomy
    vulnerability_title: str     # Title of the security report
    invariant_description: str   # State invariant claimed to be violated
    fingerprint: str             # Deterministic hash (target + root cause) to prevent front-running
    triage_bond: bigint          # Anti-spam stake (refunded if valid, slashed if spam)
    status: str                  # "PENDING", "VERIFIED", "SLASHED_SPAM", "FAILED_EVIDENCE", "CANCELLED"
    is_invariant_broken: bool    # Consensus verdict on whether the invariant is breached
    confirmed_cwe: str           # Consensus CWE taxonomy categorization
    risk_tier: str               # "CRITICAL", "HIGH", "MEDIUM", "LOW", "SPAM", "FAILED_EVIDENCE"
    impact_score: bigint         # 0 to 100 severity impact score
    evaluation_summary: str      # Consolidated jury evaluation report
    created_at: bigint
    resolved_at: bigint
    payout: bigint
    bond_refunded: bigint


class Contract(gl.Contract):
    """
    BugSlayerX: Differential Exploit & Invariant Verifier (DEPIV Protocol)
    A decentralized security verification primitive on GenLayer featuring:
    1. Dual-evidence cross-verification (Target Source Code vs PoC Reproduction Script)
    2. Anti-spam staking & slashing game theory
    3. On-chain vulnerability fingerprint registry against duplicate exploit front-running
    4. Multi-pillar semantic consensus on Invariant Breach, CWE taxonomy, and Risk Tiers
    """
    owner: Address
    report_count: bigint
    min_triage_bond: bigint
    treasury_balance: bigint
    verified_count: bigint
    slashed_spam_count: bigint
    total_bounty_paid: bigint
    reports: TreeMap[str, ExploitReport]
    vulnerability_registry: TreeMap[str, str]

    def __init__(self):
        self.owner = _get_sender()
        self.report_count = bigint(0)
        self.min_triage_bond = bigint(50)  # Minimum 50 GEN anti-spam bond
        self.treasury_balance = bigint(0)
        self.verified_count = bigint(0)
        self.slashed_spam_count = bigint(0)
        self.total_bounty_paid = bigint(0)

    def _get_current_timestamp(self) -> bigint:
        try:
            from datetime import datetime
            dt_raw = getattr(gl.message, "datetime", None)
            if dt_raw is None and hasattr(gl, "message_raw") and isinstance(gl.message_raw, dict):
                dt_raw = gl.message_raw.get("datetime")
            if dt_raw:
                dt_str = str(dt_raw).strip().replace("Z", "+00:00")
                dt = datetime.fromisoformat(dt_str)
                ts = int(dt.timestamp())
                if ts > 0:
                    return bigint(ts)
        except Exception:
            pass
        try:
            if hasattr(gl, "block") and hasattr(gl.block, "timestamp"):
                ts = int(gl.block.timestamp)
                if ts > 0:
                    return bigint(ts)
        except Exception:
            pass
        return bigint(0)

    @gl.public.view
    def get_owner(self) -> str:
        return _addr_str(self.owner)

    @gl.public.view
    def get_report_count(self) -> int:
        return int(self.report_count)

    @gl.public.view
    def get_min_triage_bond(self) -> str:
        return str(self.min_triage_bond)

    @gl.public.view
    def get_registered_exploit(self, fingerprint: str) -> str:
        """Query if a vulnerability fingerprint has already been recorded on-chain."""
        clean_fp = fingerprint.strip().lower()
        if clean_fp in self.vulnerability_registry:
            return self.vulnerability_registry[clean_fp]
        return ""

    @gl.public.write.payable
    def fund_bounty_pool(self) -> None:
        """Allow protocol owners or sponsors to fund the bounty reward treasury."""
        val = bigint(gl.message.value)
        if val <= bigint(0):
            raise gl.UserError("Must fund a positive amount of GEN.")
        self.treasury_balance += val

    @gl.public.write.payable
    def submit_exploit_report(
        self,
        target_contract_url: str,
        reproduction_poc_url: str,
        cwe_tag: str,
        vulnerability_title: str,
        invariant_description: str,
        fingerprint: str
    ) -> str:
        """
        Submit a security vulnerability with dual evidence sources and anti-spam bond.
        Prevents duplicate submissions via deterministic vulnerability fingerprinting.
        """
        bond = bigint(gl.message.value)
        if bond < self.min_triage_bond:
            raise gl.UserError(f"Insufficient triage bond. Minimum required is {self.min_triage_bond} GEN.")

        clean_target = _validate_url(target_contract_url)
        clean_poc = _validate_url(reproduction_poc_url)
        if clean_target.lower() == clean_poc.lower():
            raise gl.UserError("Target source and reproduction PoC must be distinct URLs.")

        clean_title = vulnerability_title.strip()
        clean_inv = invariant_description.strip()
        clean_cwe = cwe_tag.strip().upper()
        clean_fp = fingerprint.strip().lower()

        if len(clean_title) < 5:
            raise gl.UserError("Vulnerability title is too short.")
        if len(clean_inv) < 20:
            raise gl.UserError("Invariant description must be at least 20 characters.")
        if len(clean_fp) < 8:
            raise gl.UserError("Invalid vulnerability fingerprint.")

        # Duplicate front-running prevention
        if clean_fp in self.vulnerability_registry:
            existing_id = self.vulnerability_registry[clean_fp]
            raise gl.UserError(f"Duplicate exploit detected. Vulnerability fingerprint already verified in Report #{existing_id}.")

        self.report_count += bigint(1)
        rid = str(self.report_count)
        now_ts = self._get_current_timestamp()

        self.reports[rid] = ExploitReport(
            report_id=rid,
            researcher=_get_sender(),
            target_contract_url=clean_target,
            reproduction_poc_url=clean_poc,
            cwe_tag=clean_cwe,
            vulnerability_title=clean_title,
            invariant_description=clean_inv,
            fingerprint=clean_fp,
            triage_bond=bond,
            status="PENDING",
            is_invariant_broken=False,
            confirmed_cwe="PENDING",
            risk_tier="PENDING",
            impact_score=bigint(0),
            evaluation_summary="Awaiting multi-pillar differential consensus.",
            created_at=now_ts if now_ts > bigint(0) else self.report_count,
            resolved_at=bigint(0),
            payout=bigint(0),
            bond_refunded=bigint(0)
        )
        return rid

    @gl.public.write
    def verify_exploit(self, report_id: str) -> None:
        """
        Cross-verify the target contract code against the reproduction PoC test on-chain.
        Executes GenLayer LLM jury consensus across invariant breach, CWE, and risk severity.
        """
        if report_id not in self.reports:
            raise gl.UserError("Report not found.")

        rep = self.reports[report_id]
        if rep.status != "PENDING":
            raise gl.UserError("Report has already been resolved.")

        target_url = str(rep.target_contract_url)
        poc_url = str(rep.reproduction_poc_url)
        title_local = str(rep.vulnerability_title)
        inv_local = str(rep.invariant_description)
        cwe_claimed = str(rep.cwe_tag)

        def leader_fn():
            # Source 1: Target Contract Source
            target_code = ""
            try:
                res1 = gl.nondet.web.render(target_url, mode="text")
                if hasattr(res1, "content"):
                    target_code = res1.content
                elif isinstance(res1, dict) and "body" in res1:
                    target_code = res1["body"]
                else:
                    target_code = str(res1)
            except Exception:
                target_code = ""

            # Source 2: Reproduction PoC Test
            poc_code = ""
            try:
                res2 = gl.nondet.web.render(poc_url, mode="text")
                if hasattr(res2, "content"):
                    poc_code = res2.content
                elif isinstance(res2, dict) and "body" in res2:
                    poc_code = res2["body"]
                else:
                    poc_code = str(res2)
            except Exception:
                poc_code = ""

            lower_target = target_code[:500].lower() if target_code else ""
            lower_poc = poc_code[:500].lower() if poc_code else ""

            # Check accessibility of both independent evidence sources
            if len(target_code.strip()) < 15 or "404 not found" in lower_target or len(poc_code.strip()) < 15 or "404 not found" in lower_poc:
                return {
                    "is_invariant_broken": False,
                    "confirmed_cwe": "FAILED_EVIDENCE",
                    "risk_tier": "FAILED_EVIDENCE",
                    "impact_score": 0,
                    "evaluation_summary": "One or more evidence sources (Target Source or PoC) are inaccessible."
                }

            snippet_target = target_code[:2500]
            snippet_poc = poc_code[:2500]

            prompt = f"""You are the Lead Smart Contract Security Auditor on the GenLayer Adjudication Jury.
Perform a differential cross-verification between the Target Contract Source and the Reproduction PoC Script.

REPORT TITLE: {title_local}
CLAIMED INVARIANT BREACH: {inv_local}
CLAIMED CWE TAXONOMY: {cwe_claimed}

=== EVIDENCE SOURCE 1: TARGET CONTRACT SOURCE CODE ===
\"\"\"
{snippet_target}
\"\"\"

=== EVIDENCE SOURCE 2: REPRODUCTION PoC TEST SCRIPT ===
\"\"\"
{snippet_poc}
\"\"\"

DIFFERENTIAL ANALYSIS REQUIREMENTS:
1. Examine if the PoC script genuinely executes against the target contract logic and successfully demonstrates an invariant violation.
2. If the report is a false positive, spam, fabricated, or does NOT breach the invariant, set is_invariant_broken = false, risk_tier = "SPAM", and confirmed_cwe = "SPAM_INVALID".
3. Otherwise, classify confirmed_cwe into: "REENTRANCY", "ACCESS_CONTROL", "ORACLE_MANIPULATION", "ARITHMETIC_OVERFLOW", or "LOGIC_INVARIANT_DRAIN".
4. Determine risk_tier: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "SPAM".
5. Assign impact_score between 0 and 100 (0 for spam/invalid, 100 for fatal fund loss).
6. Provide a concise technical justification (max 250 characters).

OUTPUT FORMAT:
Respond ONLY with a VALID JSON object (no markdown, no backticks):
{{
  "is_invariant_broken": true | false,
  "confirmed_cwe": "REENTRANCY" | "ACCESS_CONTROL" | "ORACLE_MANIPULATION" | "ARITHMETIC_OVERFLOW" | "LOGIC_INVARIANT_DRAIN" | "SPAM_INVALID",
  "risk_tier": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SPAM",
  "impact_score": <integer 0-100>,
  "evaluation_summary": "<concise technical verdict>"
}}"""

            try:
                raw_res = gl.nondet.exec_prompt(prompt, response_format="json")
                parsed = None
                if isinstance(raw_res, dict):
                    parsed = raw_res
                elif hasattr(raw_res, "content") and isinstance(raw_res.content, dict):
                    parsed = raw_res.content
                else:
                    text = raw_res.content if hasattr(raw_res, "content") else str(raw_res)
                    cleaned = str(text).strip()
                    if cleaned.startswith("```json"):
                        cleaned = cleaned[7:]
                    elif cleaned.startswith("```"):
                        cleaned = cleaned[3:]
                    if cleaned.endswith("```"):
                        cleaned = cleaned[:-3]
                    parsed = json.loads(cleaned.strip())

                inv_broken = bool(parsed.get("is_invariant_broken", False))
                cwe = str(parsed.get("confirmed_cwe", "SPAM_INVALID")).strip().upper()
                valid_cwes = ("REENTRANCY", "ACCESS_CONTROL", "ORACLE_MANIPULATION", "ARITHMETIC_OVERFLOW", "LOGIC_INVARIANT_DRAIN", "SPAM_INVALID", "FAILED_EVIDENCE")
                if cwe not in valid_cwes:
                    cwe = "SPAM_INVALID"

                tier = str(parsed.get("risk_tier", "SPAM")).strip().upper()
                valid_tiers = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SPAM", "FAILED_EVIDENCE")
                if tier not in valid_tiers:
                    tier = "SPAM"

                score = int(parsed.get("impact_score", 0))
                score = max(0, min(100, score))
                summary = str(parsed.get("evaluation_summary", "Differential evaluated."))[:250]

                return {
                    "is_invariant_broken": inv_broken,
                    "confirmed_cwe": cwe,
                    "risk_tier": tier,
                    "impact_score": score,
                    "evaluation_summary": summary
                }
            except Exception as e:
                return {
                    "is_invariant_broken": False,
                    "confirmed_cwe": "FAILED_EVIDENCE",
                    "risk_tier": "FAILED_EVIDENCE",
                    "impact_score": 0,
                    "evaluation_summary": f"Audit execution error: {str(e)[:100]}"
                }

        def validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False
            leader = leader_res.calldata
            if not isinstance(leader, dict) or "risk_tier" not in leader:
                return False

            mine = leader_fn()

            # 1. Semantic match on invariant violation
            if mine.get("is_invariant_broken") != leader.get("is_invariant_broken"):
                return False

            # 2. Semantic match on Risk Tier
            if str(mine.get("risk_tier", "")).strip().upper() != str(leader.get("risk_tier", "")).strip().upper():
                return False

            # 3. Semantic match on CWE Classification
            if str(mine.get("confirmed_cwe", "")).strip().upper() != str(leader.get("confirmed_cwe", "")).strip().upper():
                return False

            # 4. Impact score tolerance bound (delta <= 20 points)
            if leader.get("risk_tier") != "FAILED_EVIDENCE":
                l_score = int(leader.get("impact_score", 0))
                m_score = int(mine.get("impact_score", 0))
                if abs(l_score - m_score) > 20:
                    return False

            return True

        adjudication_res = gl.vm.run_nondet(leader_fn, validator_fn)
        if isinstance(adjudication_res, dict):
            final_res = adjudication_res
        else:
            try:
                final_res = json.loads(str(adjudication_res))
            except Exception:
                final_res = {
                    "is_invariant_broken": False,
                    "confirmed_cwe": "FAILED_EVIDENCE",
                    "risk_tier": "FAILED_EVIDENCE",
                    "impact_score": 0,
                    "evaluation_summary": "Consensus parse error."
                }

        is_broken = bool(final_res.get("is_invariant_broken", False))
        cwe_final = str(final_res.get("confirmed_cwe", "FAILED_EVIDENCE")).strip().upper()
        tier_final = str(final_res.get("risk_tier", "FAILED_EVIDENCE")).strip().upper()
        score_final = max(0, min(100, int(final_res.get("impact_score", 0))))
        summary_final = str(final_res.get("evaluation_summary", "Adjudicated."))

        rep.is_invariant_broken = is_broken
        rep.confirmed_cwe = cwe_final
        rep.risk_tier = tier_final
        rep.impact_score = bigint(score_final)
        rep.evaluation_summary = summary_final

        now_ts = self._get_current_timestamp()
        rep.resolved_at = now_ts if now_ts > bigint(0) else self.report_count

        # Settlement Game Theory:
        if tier_final == "FAILED_EVIDENCE":
            # Inaccessible evidence: 100% refund of bond, no penalties
            rep.status = "FAILED_EVIDENCE"
            rep.payout = bigint(0)
            rep.bond_refunded = rep.triage_bond
            self.reports[report_id] = rep
            _safe_transfer(rep.researcher, rep.triage_bond)

        elif not is_broken or tier_final == "SPAM" or cwe_final == "SPAM_INVALID":
            # Anti-spam game theory: slash bond into protocol treasury
            rep.status = "SLASHED_SPAM"
            rep.payout = bigint(0)
            rep.bond_refunded = bigint(0)
            self.treasury_balance += rep.triage_bond
            self.slashed_spam_count += bigint(1)
            self.reports[report_id] = rep

        else:
            # Verified valid exploit: refund bond + calculate reward payout
            rep.status = "VERIFIED"
            self.verified_count += bigint(1)
            self.vulnerability_registry[rep.fingerprint] = report_id

            # Base reward calculation scaled by impact score and tier
            base_reward = rep.triage_bond * bigint(2)  # Base 2x multiplier
            if tier_final == "CRITICAL":
                bonus = bigint(score_final) * bigint(5)
            elif tier_final == "HIGH":
                bonus = bigint(score_final) * bigint(3)
            elif tier_final == "MEDIUM":
                bonus = bigint(score_final) * bigint(2)
            else:
                bonus = bigint(score_final)

            total_reward = base_reward + bonus
            # Disburse from treasury if available
            available = self.treasury_balance
            actual_payout = total_reward if total_reward <= available else available
            if actual_payout > bigint(0):
                self.treasury_balance -= actual_payout

            rep.payout = actual_payout
            rep.bond_refunded = rep.triage_bond
            self.total_bounty_paid += actual_payout
            self.reports[report_id] = rep

            # Transfer bond refund + earned bounty to researcher
            disbursement = rep.triage_bond + actual_payout
            _safe_transfer(rep.researcher, disbursement)

    @gl.public.write
    def cancel_pending_report(self, report_id: str) -> None:
        """Allow researcher to withdraw pending report and reclaim their staked triage bond."""
        if report_id not in self.reports:
            raise gl.UserError("Report not found.")

        rep = self.reports[report_id]
        if rep.status != "PENDING":
            raise gl.UserError("Only pending reports can be cancelled.")

        if _addr_str(_get_sender()) != _addr_str(rep.researcher):
            raise gl.UserError("Only the original researcher can cancel this report.")

        rep.status = "CANCELLED"
        rep.risk_tier = "CANCELLED"
        rep.evaluation_summary = "Cancelled by researcher prior to verification."
        refund = rep.triage_bond
        rep.bond_refunded = refund
        rep.payout = bigint(0)
        now_ts = self._get_current_timestamp()
        rep.resolved_at = now_ts if now_ts > bigint(0) else self.report_count
        self.reports[report_id] = rep

        _safe_transfer(rep.researcher, refund)

    @gl.public.view
    def get_report(self, report_id: str) -> str:
        if report_id not in self.reports:
            raise gl.UserError("Report not found.")
        r = self.reports[report_id]
        return json.dumps({
            "report_id": r.report_id,
            "researcher": _addr_str(r.researcher),
            "target_contract_url": r.target_contract_url,
            "reproduction_poc_url": r.reproduction_poc_url,
            "cwe_tag": r.cwe_tag,
            "vulnerability_title": r.vulnerability_title,
            "invariant_description": r.invariant_description,
            "fingerprint": r.fingerprint,
            "triage_bond": str(r.triage_bond),
            "status": r.status,
            "is_invariant_broken": r.is_invariant_broken,
            "confirmed_cwe": r.confirmed_cwe,
            "risk_tier": r.risk_tier,
            "impact_score": int(r.impact_score),
            "evaluation_summary": r.evaluation_summary,
            "created_at": str(r.created_at),
            "resolved_at": str(r.resolved_at),
            "payout": str(r.payout),
            "bond_refunded": str(r.bond_refunded)
        })

    @gl.public.view
    def get_stats(self) -> str:
        return json.dumps({
            "total_reports": int(self.report_count),
            "verified_count": int(self.verified_count),
            "slashed_spam_count": int(self.slashed_spam_count),
            "treasury_balance": str(self.treasury_balance),
            "total_bounty_paid": str(self.total_bounty_paid)
        })
