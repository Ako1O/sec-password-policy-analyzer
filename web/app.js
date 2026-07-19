// Client-side re-implementation of the password_policy_analyzer rules,
// for an easy, no-install demo. The canonical logic lives in the Python
// package (password_policy_analyzer/analyzer.py); keep this in sync with it.

const BLOCKLIST = new Set([
  "password",
  "123456",
  "12345678",
  "qwerty",
  "letmein",
  "admin",
  "welcome",
  "password1",
  "password1!",
  "iloveyou",
  "monkey",
  "dragon",
  "football",
  "111111",
]);

const SYMBOL_RE = /[!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~]/;

function readPolicy() {
  const contextWords = document
    .getElementById("context-words")
    .value.split(",")
    .map((w) => w.trim())
    .filter(Boolean);

  return {
    minLength: Number(document.getElementById("min-length").value) || 0,
    maxLength: Number(document.getElementById("max-length").value) || 0,
    requireUpper: document.getElementById("require-upper").checked,
    requireLower: document.getElementById("require-lower").checked,
    requireDigit: document.getElementById("require-digit").checked,
    requireSymbol: document.getElementById("require-symbol").checked,
    checkBlocklist: document.getElementById("check-blocklist").checked,
    forbidContext: document.getElementById("forbid-context").checked,
    contextWords,
  };
}

function analyzePassword(password, policy) {
  const violations = [];

  if (password.length < policy.minLength) {
    violations.push({
      code: "length_too_short",
      message: `Password must be at least ${policy.minLength} characters.`,
      help: "Long passphrases are usually easier to remember and harder to guess.",
    });
  }
  if (policy.maxLength && password.length > policy.maxLength) {
    violations.push({
      code: "length_too_long",
      message: `Password must be at most ${policy.maxLength} characters.`,
      help: "Rejecting (not truncating) avoids surprising login bugs.",
    });
  }

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = SYMBOL_RE.test(password);

  if (policy.requireUpper && !hasUpper) {
    violations.push({ code: "missing_upper", message: "Add at least one uppercase letter (A–Z)." });
  }
  if (policy.requireLower && !hasLower) {
    violations.push({ code: "missing_lower", message: "Add at least one lowercase letter (a–z)." });
  }
  if (policy.requireDigit && !hasDigit) {
    violations.push({ code: "missing_digit", message: "Add at least one digit (0–9)." });
  }
  if (policy.requireSymbol && !hasSymbol) {
    violations.push({
      code: "missing_symbol",
      message: "Add at least one symbol (example: ! or #).",
    });
  }

  if (policy.forbidContext && policy.contextWords.length && password) {
    const lowered = password.toLowerCase();
    const hit = policy.contextWords.find((w) => w && lowered.includes(w.toLowerCase()));
    if (hit) {
      violations.push({
        code: "contains_context_word",
        message: `Password contains a context word: '${hit}'.`,
        help: "Avoid using your name/username/company name inside passwords.",
      });
    }
  }

  if (policy.checkBlocklist && BLOCKLIST.has(password.toLowerCase())) {
    violations.push({
      code: "blocklisted_password",
      message: "This password is in a common/weak password list.",
      help: "Pick something unique — avoid small edits like adding '1!' to a common word.",
    });
  }

  const suggestions = [];
  if (password.length < Math.max(14, policy.minLength)) {
    suggestions.push("Consider using a longer passphrase (14+ characters) for better security.");
  }
  if (password && (password === password.toLowerCase() || password === password.toUpperCase())) {
    suggestions.push(
      "Mixing words or using a multi-word passphrase can improve strength and memorability."
    );
  }
  suggestions.push("Use unique passwords per site (a password manager helps).");

  const codes = new Set(violations.map((v) => v.code));
  const score = scorePassword(password, codes);

  return {
    isCompliant: violations.length === 0,
    score,
    rating: ratingForScore(score),
    violations,
    suggestions,
  };
}

function scorePassword(password, codes) {
  const lengthScore = Math.min(password.length, 20) * 3; // up to 60
  const classes =
    (/[A-Z]/.test(password) ? 1 : 0) +
    (/[a-z]/.test(password) ? 1 : 0) +
    (/[0-9]/.test(password) ? 1 : 0) +
    (SYMBOL_RE.test(password) ? 1 : 0);
  const varietyScore = classes * 10; // up to 40

  let score = lengthScore + varietyScore;

  if (codes.has("length_too_short")) score -= 15;
  if (codes.has("contains_context_word")) score -= 25;
  if (codes.has("blocklisted_password")) score -= 40;

  return Math.max(0, Math.min(100, score));
}

function ratingForScore(score) {
  if (score >= 80) return "Strong";
  if (score >= 60) return "Good";
  if (score >= 40) return "Fair";
  return "Weak";
}

function ratingColor(rating) {
  switch (rating) {
    case "Strong":
      return "var(--strong)";
    case "Good":
      return "var(--good)";
    case "Fair":
      return "var(--fair)";
    default:
      return "var(--weak)";
  }
}

function render() {
  const password = document.getElementById("password-input").value;
  const policy = readPolicy();
  const result = analyzePassword(password, policy);

  const fill = document.getElementById("strength-bar-fill");
  const ratingEl = document.getElementById("strength-rating");
  const scoreEl = document.getElementById("strength-score");

  fill.style.width = `${result.score}%`;
  fill.style.backgroundColor = password ? ratingColor(result.rating) : "";
  ratingEl.textContent = password ? result.rating : "—";
  ratingEl.style.color = password ? ratingColor(result.rating) : "";
  scoreEl.textContent = `${result.score} / 100`;

  const banner = document.getElementById("compliance-banner");
  if (!password) {
    banner.className = "banner banner-neutral";
    banner.textContent = "Start typing to see whether this password meets the policy.";
  } else if (result.isCompliant) {
    banner.className = "banner banner-ok";
    banner.textContent = "Compliant — this password meets the policy.";
  } else {
    banner.className = "banner banner-danger";
    banner.textContent = "Not compliant — this password fails the policy.";
  }

  const violationsBlock = document.getElementById("violations-block");
  const violationsList = document.getElementById("violations-list");
  violationsList.innerHTML = "";
  if (password && result.violations.length) {
    violationsBlock.classList.remove("hidden");
    for (const v of result.violations) {
      const li = document.createElement("li");
      li.textContent = v.message;
      if (v.help) {
        const help = document.createElement("span");
        help.className = "help";
        help.textContent = `↳ ${v.help}`;
        li.appendChild(help);
      }
      violationsList.appendChild(li);
    }
  } else {
    violationsBlock.classList.add("hidden");
  }

  const suggestionsBlock = document.getElementById("suggestions-block");
  const suggestionsList = document.getElementById("suggestions-list");
  suggestionsList.innerHTML = "";
  if (password) {
    suggestionsBlock.classList.remove("hidden");
    for (const tip of result.suggestions) {
      const li = document.createElement("li");
      li.textContent = tip;
      suggestionsList.appendChild(li);
    }
  } else {
    suggestionsBlock.classList.add("hidden");
  }
}

document.getElementById("password-input").addEventListener("input", render);

for (const id of [
  "min-length",
  "max-length",
  "require-upper",
  "require-lower",
  "require-digit",
  "require-symbol",
  "check-blocklist",
  "forbid-context",
  "context-words",
]) {
  document.getElementById(id).addEventListener("input", render);
}

const toggleBtn = document.getElementById("toggle-visibility");
toggleBtn.addEventListener("click", () => {
  const input = document.getElementById("password-input");
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  toggleBtn.textContent = isHidden ? "Hide" : "Show";
});

render();
