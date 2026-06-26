from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from math import isclose

from app.schemas import (
    AnalyzeTicketRequest,
    AnalyzeTicketResponse,
    CaseType,
    Department,
    EvidenceVerdict,
    Severity,
    Transaction,
)


BANGLA_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")
BDT_HINTS = ("taka", "tk", "bdt", "৳", "à¦Ÿà¦¾à¦•া")
BN_PIN = "\u09aa\u09bf\u09a8"
BN_OTP = "\u0993\u099f\u09bf\u09aa\u09bf"
BN_DO_NOT_SHARE = (
    "\u0985\u09a8\u09c1\u0997\u09cd\u09b0\u09b9 \u0995\u09b0\u09c7 \u0995\u09be\u09b0\u0993 \u09b8\u09be\u09a5\u09c7 "
    "\u0986\u09aa\u09a8\u09be\u09b0 \u09aa\u09bf\u09a8 \u09ac\u09be \u0993\u099f\u09bf\u09aa\u09bf "
    "\u09b6\u09c7\u09df\u09be\u09b0 \u0995\u09b0\u09ac\u09c7\u09a8 \u09a8\u09be\u0964"
)
BN_CASH_IN_REPLY_TEMPLATE = (
    "\u0986\u09aa\u09a8\u09be\u09b0 \u09b2\u09c7\u09a8\u09a6\u09c7\u09a8 {txn} \u098f\u09b0 "
    "\u09ac\u09bf\u09b7\u09df\u09c7 \u0986\u09ae\u09b0\u09be \u0985\u09ac\u0997\u09a4 \u09b9\u09df\u09c7\u099b\u09bf\u0964 "
    "\u0986\u09ae\u09be\u09a6\u09c7\u09b0 \u098f\u099c\u09c7\u09a8\u09cd\u099f \u0985\u09aa\u09be\u09b0\u09c7\u09b6\u09a8\u09b8 "
    "\u09a6\u09b2 \u098f\u099f\u09bf \u09a6\u09cd\u09b0\u09c1\u09a4 \u09af\u09be\u099a\u09be\u0987 \u0995\u09b0\u09ac\u09c7 "
    "\u098f\u09ac\u0982 \u0985\u09ab\u09bf\u09b8\u09bf\u09df\u09be\u09b2 \u099a\u09cd\u09af\u09be\u09a8\u09c7\u09b2\u09c7 "
    "\u0986\u09aa\u09a8\u09be\u0995\u09c7 \u099c\u09be\u09a8\u09be\u09ac\u09c7\u0964 "
    + BN_DO_NOT_SHARE
)


@dataclass(frozen=True)
class AnalysisContext:
    text: str
    lowered: str
    amounts: list[float]
    mentioned_transaction_ids: set[str]
    language: str
    adversarial: bool


def analyze_ticket(payload: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    ctx = _build_context(payload)
    case_type = _classify_case(payload, ctx)

    if case_type == "phishing_or_social_engineering":
        response = _analyze_phishing(payload, ctx)
    elif case_type == "duplicate_payment":
        response = _analyze_duplicate_payment(payload, ctx)
    elif case_type == "merchant_settlement_delay":
        response = _analyze_merchant_settlement(payload, ctx)
    elif case_type == "agent_cash_in_issue":
        response = _analyze_agent_cash_in(payload, ctx)
    elif case_type == "payment_failed":
        response = _analyze_payment_failed(payload, ctx)
    elif case_type == "refund_request":
        response = _analyze_refund_request(payload, ctx)
    elif case_type == "wrong_transfer":
        response = _analyze_wrong_transfer(payload, ctx)
    else:
        response = _analyze_other(payload, ctx)

    return _apply_safety_guardrails(response, ctx)


def _build_context(payload: AnalyzeTicketRequest) -> AnalysisContext:
    text = payload.complaint.strip()
    normalized = text.translate(BANGLA_DIGITS)
    lowered = normalized.casefold()
    amounts = _extract_amounts(normalized)
    mentioned_ids = {
        txn.transaction_id
        for txn in payload.transaction_history
        if txn.transaction_id.casefold() in lowered
    }
    language = payload.language or _detect_language(text)
    adversarial = _contains_any(
        lowered,
        [
            "ignore previous",
            "ignore the above",
            "system prompt",
            "developer message",
            "forget your rules",
            "override",
            "reveal secret",
            "ask for otp",
            "ask for pin",
            "do not mention otp",
            "do not mention pin",
        ],
    )
    return AnalysisContext(
        text=normalized,
        lowered=lowered,
        amounts=amounts,
        mentioned_transaction_ids=mentioned_ids,
        language=language,
        adversarial=adversarial,
    )


def _classify_case(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> CaseType:
    t = ctx.lowered
    user_type = payload.user_type or "unknown"
    channel = payload.channel or ""

    if _contains_any(
        t,
        [
            "otp",
            "pin",
            "password",
            "phishing",
            "scam",
            "fraud",
            "social engineering",
            "account will be blocked",
            "share it",
            "à¦“à¦Ÿিপি",
            "পিন",
            "à¦ªà¦¾à¦¸à¦“য়ার্ড",
            "à¦ªà¦¾à¦¸à¦“à§Ÿার্ড",
        ],
    ) and _contains_any(
        t,
        [
            "called",
            "caller",
            "someone",
            "claim",
            "saying they are from",
            "share",
            "blocked",
            "real",
            "à¦«à§‹ন",
            "à¦•ল",
            "à¦šà§‡à¦¯à¦¼à§‡à¦›à§‡",
            "à¦šà§‡à§Ÿà§‡à¦›à§‡",
            "à¦¶à§‡à§Ÿার",
        ],
    ):
        return "phishing_or_social_engineering"

    if _contains_any(t, ["twice", "double", "duplicate", "deducted twice", "paid twice", "à¦¦à§à¦‡বার", "ডাবল"]):
        return "duplicate_payment"

    if _contains_any(t, ["settlement", "settled", "sales", "batch", "সেটেল"]):
        return "merchant_settlement_delay"
    if (user_type == "merchant" or channel == "merchant_portal") and _contains_any(
        t, ["not settled", "not been settled", "delay", "delayed", "pending", "yesterday", "সেটেল"]
    ):
        return "merchant_settlement_delay"


    if ctx.language in {"bn", "mixed"} and any(
        txn.type == "cash_in"
        and (not ctx.amounts or any(_amount_equal(txn.amount, amount) for amount in ctx.amounts))
        for txn in payload.transaction_history
    ):
        return "agent_cash_in_issue"

    if _contains_any(
        t,
        [
            "cash in",
            "cash-in",
            "cashin",
            "agent",
            "balance not",
            "not reflected",
            "à¦à¦œà§‡à¦¨à§à¦Ÿ",
            "à¦•্যাশ à¦‡ন",
            "à¦•à§à¦¯à¦¾à¦¶à¦‡ন",
            "à¦¬à§à¦¯à¦¾à¦²à§‡ন্স",
            "à¦†à¦¸à§‡নি",
        ],
    ):
        if _contains_any(t, ["cash", "agent", "balance", "à¦à¦œà§‡à¦¨à§à¦Ÿ", "à¦•্যাশ", "à¦¬à§à¦¯à¦¾à¦²à§‡ন্স"]):
            return "agent_cash_in_issue"

    if _contains_any(
        t,
        [
            "failed",
            "failure",
            "balance was deducted",
            "deducted",
            "mobile recharge",
            "recharge",
            "à¦«à§‡à¦‡ল",
            "ব্যর্থ",
            "à¦•à§‡à¦Ÿà§‡",
        ],
    ) and _contains_any(t, ["payment", "pay", "recharge", "balance", "deducted", "à¦ªà§‡à¦®à§‡à¦¨à§à¦Ÿ", "à¦°à¦¿à¦šà¦¾à¦°à§à¦œ"]):
        return "payment_failed"

    if _contains_any(t, ["refund", "return my money", "changed my mind", "don't want", "cancel", "রিফান্ড", "à¦«à§‡রত"]):
        return "refund_request"

    if _contains_any(
        t,
        [
            "wrong number",
            "wrong person",
            "mistake",
            "typed it wrong",
            "reverse it",
            "didn't get",
            "did not get",
            "not received",
            "not get it",
            "send",
            "sent",
            "transfer",
            "ভুল",
            "à¦ªà¦¾à¦ à¦¿à¦¯à¦¼à§‡à¦›ি",
            "à¦ªà¦¾à¦ à¦¿à§Ÿà§‡à¦›ি",
            "à¦ªà¦¾à§Ÿনি",
        ],
    ):
        return "wrong_transfer"

    if _contains_any(t, ["money", "amount", "balance", "transaction", "à¦Ÿà¦¾à¦•া", "à¦¬à§à¦¯à¦¾à¦²à§‡ন্স", "à¦²à§‡à¦¨à¦¦à§‡ন"]):
        return "other"

    return "other"


def _analyze_phishing(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    reason_codes = ["phishing", "credential_protection", "critical_escalation"]
    if ctx.adversarial:
        reason_codes.append("prompt_injection_ignored")
    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="phishing_or_social_engineering",
        severity="critical",
        department="fraud_risk",
        agent_summary=(
            "Customer reports a likely social engineering attempt involving a request for sensitive "
            "credentials such as OTP, PIN, or password."
        ),
        recommended_next_action=(
            "Escalate to fraud_risk immediately, remind the customer that support never asks for "
            "credentials, and log any reported caller or message details for fraud analysis."
        ),
        customer_reply=(
            "Thank you for reaching out before sharing any information. We never ask for your PIN, "
            "OTP, or password under any circumstances. Please do not share these with anyone, even "
            "if they claim to be from us. Our fraud team has been notified of this incident."
        ),
        human_review_required=True,
        confidence=0.95,
        reason_codes=reason_codes,
    )


def _analyze_duplicate_payment(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    pair = _find_duplicate_pair(payload.transaction_history, ctx)
    if pair:
        first, duplicate = pair
        amount = _format_amount(duplicate.amount)
        counterparty = duplicate.counterparty or "the same counterparty"
        return _response(
            payload=payload,
            relevant_transaction_id=duplicate.transaction_id,
            evidence_verdict="consistent",
            case_type="duplicate_payment",
            severity="high",
            department="payments_ops",
            agent_summary=(
                f"Customer reports a duplicate payment. Transactions {first.transaction_id} and "
                f"{duplicate.transaction_id} are both {_format_amount(first.amount)} BDT payments "
                f"to {counterparty} close together; {duplicate.transaction_id} is the likely duplicate."
            ),
            recommended_next_action=(
                f"Verify the duplicate with payments_ops and the biller or merchant. If only one "
                f"payment is valid, initiate reversal review for {duplicate.transaction_id}."
            ),
            customer_reply=(
                f"We have noted the possible duplicate payment for transaction {duplicate.transaction_id}. "
                "Our payments team will verify the case and any eligible amount will be returned through "
                "official channels. Please do not share your PIN or OTP with anyone."
            ),
            human_review_required=True,
            confidence=0.93,
            reason_codes=["duplicate_payment", "matching_amount_counterparty", "verification_required"],
        )

    relevant = _best_transaction(
        payload.transaction_history,
        ctx,
        expected_types={"payment"},
        preferred_statuses={"completed"},
    )
    return _response(
        payload=payload,
        relevant_transaction_id=relevant.transaction_id if relevant else None,
        evidence_verdict="insufficient_data" if not relevant else "inconsistent",
        case_type="duplicate_payment",
        severity="medium",
        department="payments_ops",
        agent_summary=(
            "Customer reports a duplicate payment, but the transaction history does not contain a clear "
            "matching duplicate pair."
        ),
        recommended_next_action="Ask for the biller or merchant reference and exact payment time before initiating reversal review.",
        customer_reply=(
            "We have received your duplicate payment concern. Please share the biller or merchant reference "
            "and approximate payment time so we can verify the correct transaction. Please do not share your PIN or OTP with anyone."
        ),
        human_review_required=False,
        confidence=0.65,
        reason_codes=["duplicate_payment_claim", "needs_clarification"],
    )


def _analyze_merchant_settlement(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    txn = _best_transaction(
        payload.transaction_history,
        ctx,
        expected_types={"settlement"},
        preferred_statuses={"pending"},
    )
    if txn:
        verdict: EvidenceVerdict = "consistent" if txn.status == "pending" else "inconsistent"
        severity: Severity = "medium" if verdict == "consistent" else "low"
        status_phrase = "is pending" if txn.status == "pending" else f"is marked {txn.status}"
        return _response(
            payload=payload,
            relevant_transaction_id=txn.transaction_id,
            evidence_verdict=verdict,
            case_type="merchant_settlement_delay",
            severity=severity,
            department="merchant_operations",
            agent_summary=(
                f"Merchant reports delayed settlement of {_format_amount(txn.amount)} BDT. "
                f"Settlement {txn.transaction_id} {status_phrase}."
            ),
            recommended_next_action=(
                "Route to merchant_operations to verify settlement batch status and communicate a revised ETA if the batch is delayed."
            ),
            customer_reply=(
                f"We have noted your concern about settlement {txn.transaction_id}. Our merchant operations team will "
                "check the batch status and update you through official channels."
            ),
            human_review_required=False,
            confidence=0.9 if verdict == "consistent" else 0.72,
            reason_codes=["merchant_settlement", "pending" if txn.status == "pending" else "status_mismatch"],
        )

    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="merchant_settlement_delay",
        severity="medium",
        department="merchant_operations",
        agent_summary="Merchant reports a settlement delay, but no matching settlement transaction is available.",
        recommended_next_action="Ask for the settlement reference, date, and expected amount before escalating the batch check.",
        customer_reply=(
            "We have received your settlement concern. Please share the settlement reference, date, and expected amount "
            "so our merchant operations team can check the batch status."
        ),
        human_review_required=False,
        confidence=0.62,
        reason_codes=["merchant_settlement", "needs_clarification"],
    )


def _analyze_agent_cash_in(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    txn = _best_transaction(
        payload.transaction_history,
        ctx,
        expected_types={"cash_in"},
        preferred_statuses={"pending", "failed"},
    )
    if txn:
        verdict: EvidenceVerdict = "consistent" if txn.status in {"pending", "failed"} else "inconsistent"
        severity: Severity = "high" if verdict == "consistent" else "medium"
        reply = _bn_reply(
            txn.transaction_id,
            "à¦†পনার à¦²à§‡à¦¨à¦¦à§‡ন {txn} এর à¦¬à¦¿à¦·à§Ÿà§‡ à¦†মরা à¦…à¦¬à¦—ত à¦¹à§Ÿà§‡à¦›ি। à¦†à¦®à¦¾à¦¦à§‡র à¦à¦œà§‡à¦¨à§à¦Ÿ à¦…à¦ªà¦¾à¦°à§‡শনস দল à¦à¦Ÿি দ্রুত à¦¯à¦¾à¦šà¦¾à¦‡ à¦•à¦°à¦¬à§‡ à¦à¦¬à¦‚ à¦…à¦«à¦¿à¦¸à¦¿à§Ÿাল à¦šà§à¦¯à¦¾à¦¨à§‡à¦²à§‡ à¦†à¦ªà¦¨à¦¾à¦•à§‡ à¦œà¦¾à¦¨à¦¾à¦¬à§‡à¥¤ à¦…à¦¨à§à¦—্রহ à¦•à¦°à§‡ à¦•à¦¾à¦°à¦“ à¦¸à¦¾à¦¥à§‡ à¦†পনার পিন বা à¦“à¦Ÿিপি à¦¶à§‡à§Ÿার à¦•à¦°à¦¬à§‡ন না।",
            ctx,
        ) or (
            f"We have noted your concern about transaction {txn.transaction_id}. Our agent operations team will verify "
            "the cash-in status and update you through official channels. Please do not share your PIN or OTP with anyone."
        )
        return _response(
            payload=payload,
            relevant_transaction_id=txn.transaction_id,
            evidence_verdict=verdict,
            case_type="agent_cash_in_issue",
            severity=severity,
            department="agent_operations",
            agent_summary=(
                f"Customer reports cash-in of {_format_amount(txn.amount)} BDT via {txn.counterparty or 'an agent'} "
                f"not reflected in balance. Transaction {txn.transaction_id} status is {txn.status}."
            ),
            recommended_next_action=(
                f"Investigate {txn.transaction_id} with agent_operations, confirm settlement state, and resolve within the cash-in SLA."
            ),
            customer_reply=reply,
            human_review_required=True,
            confidence=0.88 if verdict == "consistent" else 0.72,
            reason_codes=["agent_cash_in", txn.status, "agent_ops"],
        )

    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="agent_cash_in_issue",
        severity="medium",
        department="agent_operations",
        agent_summary="Customer reports a cash-in issue, but no matching cash-in transaction is available.",
        recommended_next_action="Ask for the agent number, amount, and approximate cash-in time before opening the agent operations investigation.",
        customer_reply=(
            "We have received your cash-in concern. Please share the agent number, amount, and approximate time so we can "
            "identify the right transaction. Please do not share your PIN or OTP with anyone."
        ),
        human_review_required=False,
        confidence=0.62,
        reason_codes=["agent_cash_in", "needs_clarification"],
    )


def _analyze_payment_failed(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    txn = _best_transaction(
        payload.transaction_history,
        ctx,
        expected_types={"payment"},
        preferred_statuses={"failed"},
    )
    if txn:
        verdict: EvidenceVerdict = "consistent" if txn.status == "failed" else "inconsistent"
        return _response(
            payload=payload,
            relevant_transaction_id=txn.transaction_id,
            evidence_verdict=verdict,
            case_type="payment_failed",
            severity="high" if "deduct" in ctx.lowered or "balance" in ctx.lowered else "medium",
            department="payments_ops",
            agent_summary=(
                f"Customer reports payment failure for {_format_amount(txn.amount)} BDT. "
                f"Transaction {txn.transaction_id} status is {txn.status}; customer reports possible balance deduction."
            ),
            recommended_next_action=(
                f"Investigate {txn.transaction_id} ledger status. If balance was deducted on a failed payment, start the standard reversal flow."
            ),
            customer_reply=(
                f"We have noted that transaction {txn.transaction_id} may have caused an unexpected balance deduction. "
                "Our payments team will review the case and any eligible amount will be returned through official channels. "
                "Please do not share your PIN or OTP with anyone."
            ),
            human_review_required=False if verdict == "consistent" else True,
            confidence=0.9 if verdict == "consistent" else 0.72,
            reason_codes=["payment_failed", "potential_balance_deduction" if "deduct" in ctx.lowered else "payment_status_review"],
        )

    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="payment_failed",
        severity="medium",
        department="payments_ops",
        agent_summary="Customer reports a failed payment or deducted balance, but no matching payment transaction is available.",
        recommended_next_action="Ask for the transaction ID, amount, merchant or biller name, and approximate time.",
        customer_reply=(
            "We have received your payment concern. Please share the transaction ID, amount, merchant or biller name, "
            "and approximate time so we can verify it. Please do not share your PIN or OTP with anyone."
        ),
        human_review_required=False,
        confidence=0.6,
        reason_codes=["payment_failed_claim", "needs_clarification"],
    )


def _analyze_refund_request(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    txn = _best_transaction(
        payload.transaction_history,
        ctx,
        expected_types={"payment"},
        preferred_statuses={"completed"},
    )
    if txn:
        return _response(
            payload=payload,
            relevant_transaction_id=txn.transaction_id,
            evidence_verdict="consistent",
            case_type="refund_request",
            severity="low",
            department="customer_support",
            agent_summary=(
                f"Customer requests refund of {_format_amount(txn.amount)} BDT for {txn.transaction_id}, a completed merchant payment."
            ),
            recommended_next_action=(
                "Explain that refund eligibility depends on the merchant policy and guide the customer without promising a refund."
            ),
            customer_reply=(
                "Thank you for reaching out. Refunds for completed merchant payments depend on the merchant's policy. "
                "If you need help with the next step, reply here and we will guide you through official support. "
                "Please do not share your PIN or OTP with anyone."
            ),
            human_review_required=False,
            confidence=0.85,
            reason_codes=["refund_request", "merchant_policy_dependent"],
        )

    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="refund_request",
        severity="low",
        department="customer_support",
        agent_summary="Customer requests a refund, but no matching completed merchant payment is available.",
        recommended_next_action="Ask for the transaction ID, amount, merchant name, and purchase date before advising further.",
        customer_reply=(
            "We have received your refund request. Please share the transaction ID, amount, merchant name, and purchase date "
            "so we can guide you correctly. Please do not share your PIN or OTP with anyone."
        ),
        human_review_required=False,
        confidence=0.6,
        reason_codes=["refund_request", "needs_clarification"],
    )


def _analyze_wrong_transfer(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    ambiguous = _wrong_transfer_is_ambiguous(payload.transaction_history, ctx)
    if ambiguous:
        return _response(
            payload=payload,
            relevant_transaction_id=None,
            evidence_verdict="insufficient_data",
            case_type="wrong_transfer",
            severity="medium",
            department="dispute_resolution",
            agent_summary=(
                "Customer reports a transfer issue, but multiple transactions plausibly match the complaint. "
                "The service cannot identify the exact transaction without more details."
            ),
            recommended_next_action="Ask for the recipient number or transaction ID before initiating any dispute workflow.",
            customer_reply=(
                "Thank you for reaching out. We see multiple possible matching transfers. Could you share the recipient number "
                "or transaction ID so we can identify the right transaction? Please do not share your PIN or OTP with anyone."
            ),
            human_review_required=False,
            confidence=0.65,
            reason_codes=["ambiguous_match", "needs_clarification"],
        )

    txn = _best_transaction(
        payload.transaction_history,
        ctx,
        expected_types={"transfer"},
        preferred_statuses={"completed"},
    )
    if txn:
        established = _has_established_recipient_pattern(payload.transaction_history, txn)
        verdict: EvidenceVerdict = "inconsistent" if established else "consistent"
        severity: Severity = "medium" if established or txn.amount < 3000 else "high"
        reason_codes = ["wrong_transfer_claim" if established else "wrong_transfer", "transaction_match"]
        if established:
            reason_codes.extend(["established_recipient_pattern", "evidence_inconsistent"])
        else:
            reason_codes.append("dispute_review")

        return _response(
            payload=payload,
            relevant_transaction_id=txn.transaction_id,
            evidence_verdict=verdict,
            case_type="wrong_transfer",
            severity=severity,
            department="dispute_resolution",
            agent_summary=_wrong_transfer_summary(txn, established),
            recommended_next_action=(
                f"Verify {txn.transaction_id} details with the customer. "
                + (
                    "Because prior transfers to the same counterparty exist, confirm the claim before opening the dispute workflow."
                    if established
                    else "Initiate the wrong-transfer dispute workflow per policy after identity and transaction verification."
                )
            ),
            customer_reply=(
                f"We have received your request regarding transaction {txn.transaction_id}. Please do not share your PIN or OTP "
                "with anyone. Our dispute team will review the case carefully and contact you through official support channels."
            ),
            human_review_required=True,
            confidence=0.75 if established else 0.9,
            reason_codes=reason_codes,
        )

    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="wrong_transfer",
        severity="medium" if ctx.amounts else "low",
        department="dispute_resolution",
        agent_summary="Customer reports a transfer issue, but no matching transfer transaction can be identified from the provided history.",
        recommended_next_action="Ask for the transaction ID, recipient number, amount, and approximate time before initiating dispute review.",
        customer_reply=(
            "Thank you for reaching out. Please share the transaction ID, recipient number, amount, and approximate time so we can "
            "identify the correct transfer. Please do not share your PIN or OTP with anyone."
        ),
        human_review_required=False,
        confidence=0.6,
        reason_codes=["wrong_transfer_claim", "needs_clarification"],
    )


def _analyze_other(payload: AnalyzeTicketRequest, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    reason_codes = ["vague_complaint", "needs_clarification"]
    if ctx.adversarial:
        reason_codes.append("prompt_injection_ignored")
    return _response(
        payload=payload,
        relevant_transaction_id=None,
        evidence_verdict="insufficient_data",
        case_type="other",
        severity="low",
        department="customer_support",
        agent_summary=(
            "Customer reports a general concern without enough transaction, amount, or issue details to identify a specific case."
        ),
        recommended_next_action="Ask for the transaction ID, amount, approximate time, and a short description of what went wrong.",
        customer_reply=(
            "Thank you for reaching out. To help you faster, please share the transaction ID, the amount involved, "
            "and a short description of what went wrong. Please do not share your PIN or OTP with anyone."
        ),
        human_review_required=False,
        confidence=0.6,
        reason_codes=reason_codes,
    )


def _response(
    *,
    payload: AnalyzeTicketRequest,
    relevant_transaction_id: str | None,
    evidence_verdict: EvidenceVerdict,
    case_type: CaseType,
    severity: Severity,
    department: Department,
    agent_summary: str,
    recommended_next_action: str,
    customer_reply: str,
    human_review_required: bool,
    confidence: float,
    reason_codes: list[str],
) -> AnalyzeTicketResponse:
    return AnalyzeTicketResponse(
        ticket_id=payload.ticket_id,
        relevant_transaction_id=relevant_transaction_id,
        evidence_verdict=evidence_verdict,
        case_type=case_type,
        severity=severity,
        department=department,
        agent_summary=agent_summary,
        recommended_next_action=recommended_next_action,
        customer_reply=customer_reply,
        human_review_required=human_review_required,
        confidence=round(max(0, min(1, confidence)), 2),
        reason_codes=reason_codes,
    )


def _apply_safety_guardrails(response: AnalyzeTicketResponse, ctx: AnalysisContext) -> AnalyzeTicketResponse:
    reply = response.customer_reply

    unsafe_refund_promises = [
        r"\bwe will refund\b",
        r"\bwe will reverse\b",
        r"\brefund is confirmed\b",
        r"\breversal is confirmed\b",
        r"\baccount will be unblocked\b",
    ]
    for pattern in unsafe_refund_promises:
        reply = re.sub(pattern, "any eligible amount will be returned through official channels", reply, flags=re.IGNORECASE)

    if not _contains_any(reply.casefold(), ["pin", "otp", "password", "পিন", "à¦“à¦Ÿিপি"]):
        if ctx.language == "bn":
            reply = reply.rstrip() + " " + BN_DO_NOT_SHARE
        else:
            reply = reply.rstrip() + " Please do not share your PIN or OTP with anyone."

    reason_codes = list(response.reason_codes)
    if ctx.adversarial and "prompt_injection_ignored" not in reason_codes:
        reason_codes.append("prompt_injection_ignored")

    response.customer_reply = reply
    response.reason_codes = reason_codes
    return response


def _extract_amounts(text: str) -> list[float]:
    candidates: list[float] = []
    for match in re.finditer(r"(?<![\w.])(?:৳\s*)?(\d{2,9}(?:,\d{3})*(?:\.\d+)?)\s*(?:taka|tk|bdt|à¦Ÿà¦¾à¦•া)?", text, re.IGNORECASE):
        number = match.group(1).replace(",", "")
        try:
            value = float(number)
        except ValueError:
            continue
        # Avoid treating phone numbers and years as payment amounts.
        if value >= 10 and value < 10_000_000 and len(number.split(".")[0]) <= 7:
            candidates.append(value)
    return candidates


def _best_transaction(
    transactions: list[Transaction],
    ctx: AnalysisContext,
    *,
    expected_types: set[str],
    preferred_statuses: set[str],
) -> Transaction | None:
    if not transactions:
        return None

    scored: list[tuple[float, datetime, int, Transaction]] = []
    for index, txn in enumerate(transactions):
        score = 0.0
        if txn.transaction_id in ctx.mentioned_transaction_ids:
            score += 10
        if txn.type in expected_types:
            score += 4
        if ctx.amounts and any(_amount_equal(txn.amount, amount) for amount in ctx.amounts):
            score += 4
        elif not ctx.amounts:
            score += 0.5
        if txn.status in preferred_statuses:
            score += 2
        if txn.counterparty and txn.counterparty.casefold() in ctx.lowered:
            score += 3
        if expected_types and txn.type not in expected_types:
            score -= 2

        if score > 0:
            scored.append((score, _parse_timestamp(txn.timestamp), -index, txn))

    if not scored:
        return None

    scored.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    best_score, _, _, best = scored[0]
    if best_score < 3:
        return None
    return best


def _find_duplicate_pair(transactions: list[Transaction], ctx: AnalysisContext) -> tuple[Transaction, Transaction] | None:
    payments = [txn for txn in transactions if txn.type == "payment" and txn.status == "completed"]
    payments.sort(key=lambda txn: _parse_timestamp(txn.timestamp))
    best_pair: tuple[Transaction, Transaction] | None = None
    best_gap = float("inf")

    for i, first in enumerate(payments):
        for second in payments[i + 1 :]:
            if not _amount_equal(first.amount, second.amount):
                continue
            if first.counterparty and second.counterparty and first.counterparty != second.counterparty:
                continue
            if ctx.amounts and not any(_amount_equal(first.amount, amount) for amount in ctx.amounts):
                continue
            gap = abs((_parse_timestamp(second.timestamp) - _parse_timestamp(first.timestamp)).total_seconds())
            if gap <= 10 * 60 and gap < best_gap:
                best_pair = (first, second)
                best_gap = gap

    return best_pair


def _wrong_transfer_is_ambiguous(transactions: list[Transaction], ctx: AnalysisContext) -> bool:
    if not ctx.amounts:
        return False

    transfer_candidates = [
        txn
        for txn in transactions
        if txn.type == "transfer" and any(_amount_equal(txn.amount, amount) for amount in ctx.amounts)
    ]
    if len(transfer_candidates) <= 1:
        return False

    mentioned_counterparties = [
        txn
        for txn in transfer_candidates
        if txn.counterparty and txn.counterparty.casefold() in ctx.lowered
    ]
    mentioned_ids = [txn for txn in transfer_candidates if txn.transaction_id in ctx.mentioned_transaction_ids]
    return not mentioned_counterparties and not mentioned_ids


def _has_established_recipient_pattern(transactions: list[Transaction], target: Transaction) -> bool:
    if not target.counterparty:
        return False
    target_time = _parse_timestamp(target.timestamp)
    prior_same_recipient = [
        txn
        for txn in transactions
        if txn.transaction_id != target.transaction_id
        and txn.type == "transfer"
        and txn.status == "completed"
        and txn.counterparty == target.counterparty
        and _parse_timestamp(txn.timestamp) < target_time
    ]
    return len(prior_same_recipient) >= 2


def _wrong_transfer_summary(txn: Transaction, established: bool) -> str:
    base = (
        f"Customer reports transfer {txn.transaction_id} of {_format_amount(txn.amount)} BDT "
        f"to {txn.counterparty or 'the recipient'} as a wrong or disputed transfer."
    )
    if established:
        return base + " Prior completed transfers to the same counterparty suggest an established recipient pattern."
    return base + " The complaint details match the provided transaction history."


def _amount_equal(left: float, right: float) -> bool:
    return isclose(float(left), float(right), abs_tol=0.01)


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _format_amount(amount: float) -> str:
    if float(amount).is_integer():
        return str(int(amount))
    return f"{amount:.2f}".rstrip("0").rstrip(".")


def _detect_language(text: str) -> str:
    if re.search(r"[\u0980-\u09FF]", text):
        ascii_letters = len(re.findall(r"[A-Za-z]", text))
        bangla_letters = len(re.findall(r"[\u0980-\u09FF]", text))
        return "mixed" if ascii_letters and bangla_letters else "bn"
    return "en"


def _bn_reply(transaction_id: str, template: str, ctx: AnalysisContext) -> str | None:
    if ctx.language != "bn":
        return None
    return BN_CASH_IN_REPLY_TEMPLATE.format(txn=transaction_id)


def _contains_any(text: str, needles: list[str] | tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)
