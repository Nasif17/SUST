const samples = [
  {
    ticket_id: "TKT-001",
    complaint:
      "I sent 5000 taka to a wrong number around 2pm today. The number was supposed to be 01712345678 but I think I typed it wrong. The person isn't responding to my call. Please help me get my money back.",
    language: "en",
    channel: "in_app_chat",
    user_type: "customer",
    campaign_context: "boishakh_bonanza_day_1",
    transaction_history: [
      {
        transaction_id: "TXN-9101",
        timestamp: "2026-04-14T14:08:22Z",
        type: "transfer",
        amount: 5000,
        counterparty: "+8801719876543",
        status: "completed",
      },
      {
        transaction_id: "TXN-9087",
        timestamp: "2026-04-13T18:12:00Z",
        type: "cash_in",
        amount: 10000,
        counterparty: "AGENT-512",
        status: "completed",
      },
    ],
  },
  {
    ticket_id: "TKT-003",
    complaint:
      "I tried to pay 1200 taka for my mobile recharge but the app showed failed. But my balance was deducted! Please refund my money.",
    language: "en",
    channel: "in_app_chat",
    user_type: "customer",
    campaign_context: "",
    transaction_history: [
      {
        transaction_id: "TXN-9301",
        timestamp: "2026-04-14T16:00:00Z",
        type: "payment",
        amount: 1200,
        counterparty: "MERCHANT-MOBILE-OP",
        status: "failed",
      },
    ],
  },
  {
    ticket_id: "TKT-005",
    complaint:
      "Someone called me saying they are from bKash and asked for my OTP. They said my account will be blocked if I don't share it. Is this real? I haven't shared anything yet.",
    language: "en",
    channel: "call_center",
    user_type: "customer",
    campaign_context: "",
    transaction_history: [],
  },
  {
    ticket_id: "TKT-010",
    complaint:
      "I paid my electricity bill 850 taka but it deducted twice from my account. Please check, I only paid once.",
    language: "en",
    channel: "in_app_chat",
    user_type: "customer",
    campaign_context: "",
    transaction_history: [
      {
        transaction_id: "TXN-10001",
        timestamp: "2026-04-14T08:15:30Z",
        type: "payment",
        amount: 850,
        counterparty: "BILLER-DESCO",
        status: "completed",
      },
      {
        transaction_id: "TXN-10002",
        timestamp: "2026-04-14T08:15:42Z",
        type: "payment",
        amount: 850,
        counterparty: "BILLER-DESCO",
        status: "completed",
      },
    ],
  },
];

const form = document.querySelector("#ticketForm");
const healthBadge = document.querySelector("#healthBadge");
const sampleSelect = document.querySelector("#sampleSelect");
const loadSampleButton = document.querySelector("#loadSample");
const resetButton = document.querySelector("#resetButton");
const runButton = document.querySelector("#runButton");
const copyResultButton = document.querySelector("#copyResult");
const emptyState = document.querySelector("#emptyState");
const resultView = document.querySelector("#resultView");
const errorBox = document.querySelector("#errorBox");
const rawJson = document.querySelector("#rawJson");

let latestResult = null;

function setField(id, value) {
  document.querySelector(`#${id}`).value = value ?? "";
}

function loadSample(index) {
  const sample = samples[index] || samples[0];
  setField("ticketId", sample.ticket_id);
  setField("language", sample.language);
  setField("channel", sample.channel);
  setField("userType", sample.user_type);
  setField("complaint", sample.complaint);
  setField("campaignContext", sample.campaign_context);
  setField("transactions", JSON.stringify(sample.transaction_history, null, 2));
}

async function fetchWithFallback(paths, options) {
  let lastError;
  for (const path of paths) {
    try {
      const response = await fetch(path, options);
      if (response.status !== 404) {
        return response;
      }
      lastError = new Error(`${path} returned 404`);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

function buildPayload() {
  let transactionHistory;
  try {
    transactionHistory = JSON.parse(document.querySelector("#transactions").value || "[]");
  } catch (error) {
    throw new Error("Transaction history must be valid JSON.");
  }

  if (!Array.isArray(transactionHistory)) {
    throw new Error("Transaction history must be a JSON array.");
  }

  const payload = {
    ticket_id: document.querySelector("#ticketId").value.trim(),
    complaint: document.querySelector("#complaint").value.trim(),
    language: document.querySelector("#language").value,
    channel: document.querySelector("#channel").value,
    user_type: document.querySelector("#userType").value,
    transaction_history: transactionHistory,
  };

  const campaignContext = document.querySelector("#campaignContext").value.trim();
  if (campaignContext) {
    payload.campaign_context = campaignContext;
  }

  return payload;
}

function setHealth(ok, label) {
  healthBadge.textContent = label;
  healthBadge.classList.toggle("status-ok", ok);
  healthBadge.classList.toggle("status-error", !ok);
  healthBadge.classList.remove("status-waiting");
}

async function checkHealth() {
  try {
    const response = await fetchWithFallback(["/health", "/api/health"]);
    if (!response.ok) {
      throw new Error("Health check failed");
    }
    const body = await response.json();
    setHealth(true, body.status);
  } catch (error) {
    setHealth(false, "Offline");
  }
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function setText(id, value) {
  document.querySelector(`#${id}`).textContent = value ?? "-";
}

function renderReasonCodes(codes) {
  const target = document.querySelector("#reasonCodes");
  target.innerHTML = "";
  for (const code of codes || []) {
    const item = document.createElement("span");
    item.textContent = code;
    target.append(item);
  }
}

function renderResult(result) {
  latestResult = result;
  emptyState.classList.add("hidden");
  resultView.classList.remove("hidden");
  clearError();

  setText("caseType", result.case_type);
  setText("verdict", result.evidence_verdict);
  setText("severity", result.severity);
  setText("department", result.department);
  setText("transactionId", result.relevant_transaction_id || "no transaction");
  setText("reviewFlag", result.human_review_required ? "human review" : "auto route");
  setText("confidence", `${Math.round((result.confidence || 0) * 100)}% confidence`);
  setText("agentSummary", result.agent_summary);
  setText("nextAction", result.recommended_next_action);
  setText("customerReply", result.customer_reply);
  renderReasonCodes(result.reason_codes);

  const severity = document.querySelector("#severity");
  severity.className = "";
  severity.classList.add(`severity-${result.severity}`);

  document.querySelector("#confidenceBar").style.width = `${Math.round((result.confidence || 0) * 100)}%`;
  rawJson.textContent = JSON.stringify(result, null, 2);
}

async function submitTicket(event) {
  event.preventDefault();
  clearError();
  runButton.disabled = true;
  runButton.textContent = "Running";

  try {
    const payload = buildPayload();
    const response = await fetchWithFallback(["/analyze-ticket", "/api/analyze-ticket"], {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.detail ? JSON.stringify(body.detail) : "Analysis request failed.");
    }
    renderResult(body);
  } catch (error) {
    showError(error.message || "Analysis request failed.");
  } finally {
    runButton.disabled = false;
    runButton.textContent = "Run Analysis";
  }
}

async function copyResult() {
  if (!latestResult) {
    return;
  }
  await navigator.clipboard.writeText(JSON.stringify(latestResult, null, 2));
  copyResultButton.textContent = "Copied";
  window.setTimeout(() => {
    copyResultButton.textContent = "Copy JSON";
  }, 1000);
}

loadSampleButton.addEventListener("click", () => loadSample(Number(sampleSelect.value)));
resetButton.addEventListener("click", () => {
  form.reset();
  loadSample(0);
  resultView.classList.add("hidden");
  emptyState.classList.remove("hidden");
  latestResult = null;
  clearError();
});
copyResultButton.addEventListener("click", copyResult);
form.addEventListener("submit", submitTicket);

loadSample(0);
checkHealth();
