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
class BugReport:
    report_id: str
    researcher: Address
    vulnerability_title: str
    description: str
    poc_url: str                # GitHub commit or PoC verification link
    bounty_requested: bigint
    status: str                 # "PENDING", "VERIFIED", "REJECTED", "FAILED_EVIDENCE", "CANCELLED"
    severity: str               # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INVALID", "FAILED_EVIDENCE", "CANCELLED"
    score: bigint               # 0 to 100 severity score
    evaluation_report: str
    created_at: bigint
    resolved_at: bigint
    payout: bigint

class Contract(gl.Contract):
    """
    BugSlayerX: Autonomous Bug Bounty & Exploit Verifier Protocol on GenLayer
    """
    owner: Address
    report_count: bigint
    reports: TreeMap[str, BugReport]
    verified_count: bigint
    total_bounty_paid: bigint

    def __init__(self):
        self.owner = _get_sender()
        self.report_count = bigint(0)
        self.verified_count = bigint(0)
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

    @gl.public.write.payable
    def submit_bug_report(self, vulnerability_title: str, description: str, poc_url: str) -> str:
        """
        White-hat hacker submits a bug report with PoC URL / GitHub commit and locks/requests bounty.
        """
        bounty = bigint(gl.message.value)
        clean_title = vulnerability_title.strip()
        clean_desc = description.strip()
        clean_url = _validate_url(poc_url)

        if len(clean_title) < 5:
            raise gl.UserError("Vulnerability title is too short.")
        if len(clean_desc) < 20:
            raise gl.UserError("Description is too short.")

        self.report_count += bigint(1)
        rid = str(self.report_count)
        now_ts = self._get_current_timestamp()

        self.reports[rid] = BugReport(
            report_id=rid,
            researcher=_get_sender(),
            vulnerability_title=clean_title,
            description=clean_desc,
            poc_url=clean_url,
            bounty_requested=bounty,
            status="PENDING",
            severity="PENDING",
            score=bigint(0),
            evaluation_report="Awaiting validator vulnerability verification consensus.",
            created_at=now_ts if now_ts > bigint(0) else self.report_count,
            resolved_at=bigint(0),
            payout=bigint(0)
        )
        return rid

    @gl.public.write
    def verify_vulnerability(self, report_id: str) -> None:
        """
        Validators scrape the PoC/GitHub commit URL on-chain and utilize GenLayer LLM jury consensus
        to evaluate validity, severity, and exploit impact.
        """
        if report_id not in self.reports:
            raise gl.UserError("Bug report not found.")

        rep = self.reports[report_id]
        if rep.status != "PENDING":
            raise gl.UserError("Bug report has already been verified.")

        title_local = str(rep.vulnerability_title)
        desc_local = str(rep.description)
        url_local = str(rep.poc_url)

        def leader_fn():
            web_content = ""
            try:
                res = gl.nondet.web.render(url_local, mode="text")
                if hasattr(res, "content"):
                    web_content = res.content
                elif isinstance(res, dict) and "body" in res:
                    web_content = res["body"]
                else:
                    web_content = str(res)
            except Exception:
                web_content = ""

            lower_web = web_content[:500].lower() if web_content else ""
            if len(web_content.strip()) < 15 or "404 not found" in lower_web or "error" in lower_web:
                return {
                    "score": 0,
                    "severity": "FAILED_EVIDENCE",
                    "evaluation_report": "PoC / GitHub commit reference source is offline or inaccessible."
                }

            snippet = web_content[:4000]

            prompt = f"""You are an expert Smart Contract Security Auditor and Bug Bounty Triager.
Evaluate the validity and severity of the following vulnerability report by examining the scraped PoC / GitHub commit reference.

VULNERABILITY TITLE: {title_local}
DESCRIPTION: {desc_local}

SCRAPED PoC / COMMIT REFERENCE EVIDENCE:
\"\"\"
{snippet}
\"\"\"

EVALUATION RULES:
- Assign a score from 0 to 100 based on severity, exploitability, and impact (0 = invalid/false positive, 100 = critical zero-day exploit).
- Determine severity level: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INVALID".
- If evidence is unparsable or broken, return "FAILED_EVIDENCE".
- Provide a concise professional triage report (max 250 characters).

OUTPUT FORMAT:
Respond ONLY with a VALID JSON object (no markdown, no backticks):
{{
  "score": <integer 0-100>,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INVALID" | "FAILED_EVIDENCE",
  "evaluation_report": "<concise professional triage summary>"
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

                score = int(parsed.get("score", 0))
                score = max(0, min(100, score))
                severity = str(parsed.get("severity", "INVALID")).strip().upper()
                valid_sev = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INVALID", "FAILED_EVIDENCE")
                if severity not in valid_sev:
                    severity = "INVALID"
                report = str(parsed.get("evaluation_report", "Evaluated."))[:250]

                return {
                    "score": score,
                    "severity": severity,
                    "evaluation_report": report
                }
            except Exception as e:
                return {
                    "score": 0,
                    "severity": "FAILED_EVIDENCE",
                    "evaluation_report": f"Evaluation error: {str(e)[:100]}"
                }

        def validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False
            leader = leader_res.calldata
            if not isinstance(leader, dict) or "severity" not in leader:
                return False

            valid_sev = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INVALID", "FAILED_EVIDENCE")
            l_sev = str(leader.get("severity", "")).strip().upper()
            if l_sev not in valid_sev:
                return False

            mine = leader_fn()
            m_sev = str(mine.get("severity", "")).strip().upper()

            if l_sev != m_sev:
                return False

            if l_sev != "FAILED_EVIDENCE":
                l_score = int(leader.get("score", 0))
                m_score = int(mine.get("score", 0))
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
                final_res = {"score": 0, "severity": "FAILED_EVIDENCE", "evaluation_report": "Consensus parse failed."}

        score = int(final_res.get("score", 0))
        score_clamped = max(0, min(100, score))
        severity = str(final_res.get("severity", "FAILED_EVIDENCE")).strip().upper()
        report = str(final_res.get("evaluation_report", "Processed."))

        rep.score = bigint(score_clamped)
        rep.severity = severity
        rep.evaluation_report = report
        rep.status = "VERIFIED" if severity not in ("INVALID", "FAILED_EVIDENCE") else ("REJECTED" if severity == "INVALID" else "FAILED_EVIDENCE")
        now_ts = self._get_current_timestamp()
        rep.resolved_at = now_ts if now_ts > bigint(0) else self.report_count

        if rep.status == "VERIFIED":
            self.verified_count += bigint(1)
            payout = rep.bounty_requested
            rep.payout = payout
            self.total_bounty_paid += payout
            self.reports[report_id] = rep
            _safe_transfer(rep.researcher, payout)
        elif rep.status == "REJECTED":
            rep.payout = bigint(0)
            self.reports[report_id] = rep
        else:
            # FAILED_EVIDENCE: refund requested bounty back to researcher
            rep.payout = rep.bounty_requested
            self.reports[report_id] = rep
            _safe_transfer(rep.researcher, rep.bounty_requested)

    @gl.public.write
    def cancel_report(self, report_id: str) -> None:
        """Allow researcher to cancel pending report and withdraw requested bounty deposit if any."""
        if report_id not in self.reports:
            raise gl.UserError("Bug report not found.")

        rep = self.reports[report_id]
        if rep.status != "PENDING":
            raise gl.UserError("Only pending reports can be cancelled.")

        if _addr_str(_get_sender()) != _addr_str(rep.researcher):
            raise gl.UserError("Only researcher can cancel report.")

        rep.status = "CANCELLED"
        rep.severity = "CANCELLED"
        rep.evaluation_report = "Cancelled by researcher."
        refund = rep.bounty_requested
        rep.payout = refund
        now_ts = self._get_current_timestamp()
        rep.resolved_at = now_ts if now_ts > bigint(0) else self.report_count
        self.reports[report_id] = rep

        if refund > bigint(0):
            _safe_transfer(rep.researcher, refund)

    @gl.public.view
    def get_report(self, report_id: str) -> str:
        if report_id not in self.reports:
            raise gl.UserError("Report not found.")
        r = self.reports[report_id]
        return json.dumps({
            "report_id": r.report_id,
            "researcher": _addr_str(r.researcher),
            "vulnerability_title": r.vulnerability_title,
            "description": r.description,
            "poc_url": r.poc_url,
            "bounty_requested": str(r.bounty_requested),
            "status": r.status,
            "severity": r.severity,
            "score": int(r.score),
            "evaluation_report": r.evaluation_report,
            "created_at": str(r.created_at),
            "resolved_at": str(r.resolved_at),
            "payout": str(r.payout)
        })

    @gl.public.view
    def get_stats(self) -> str:
        return json.dumps({
            "total_reports": int(self.report_count),
            "verified_count": int(self.verified_count),
            "total_bounty_paid": str(self.total_bounty_paid)
        })
