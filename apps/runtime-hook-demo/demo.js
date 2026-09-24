"use strict";

const tokenInput = document.querySelector("#token-input");
const tokenForm = document.querySelector("#token-form");
const result = document.querySelector("#result");
const resultTitle = document.querySelector("#result-title");
const resultDetail = document.querySelector("#result-detail");
const splitValue = document.querySelector("#split-value");
const mapValue = document.querySelector("#map-value");
const checkValue = document.querySelector("#check-value");
const runCount = document.querySelector("#run-count");
let runs = 0;

// This closure deliberately keeps "salt" and the callback off window.
const processToken = (() => {
  const salt = 17;

  return (rawToken) => {
    const parts = rawToken.trim().toUpperCase().split(".");
    if (parts.length !== 3 || parts[0] !== "LAB" ||
        !/^[A-Z0-9-]{1,32}$/.test(parts[1]) || !/^[0-9A-Z]{2}$/.test(parts[2])) {
      throw new Error("Use LAB.PAYLOAD.CHECK with 1–32 letters, digits, or hyphens in the payload.");
    }

    const [prefix, payload, received] = parts;
    const scores = Array.from(payload).map((character, index) => {
      const code = character.charCodeAt(0);
      const weighted = (code * (index + 1) + salt) % 97; // REB cursor: this callback
      return weighted;
    });
    const total = scores.reduce((sum, score) => sum + score, 0);
    const expected = (total % 97).toString(36).toUpperCase().padStart(2, "0");

    return { prefix, payload, received, scores, expected, valid: received === expected };
  };
})();

const sampleResult = processToken("LAB.PIXEL-42.00");
const validSample = `LAB.PIXEL-42.${sampleResult.expected}`;
const tamperedSample = `LAB.PIXEL-42.${sampleResult.expected === "00" ? "01" : "00"}`;
tokenInput.value = validSample;

function setResult(state, title, detail) {
  result.className = `result ${state}`;
  resultTitle.textContent = title;
  resultDetail.textContent = detail;
}

document.querySelector("#sample-button").addEventListener("click", () => {
  tokenInput.value = validSample;
  tokenInput.focus();
});
document.querySelector("#tamper-button").addEventListener("click", () => {
  tokenInput.value = tamperedSample;
  tokenInput.focus();
});

tokenForm.addEventListener("submit", (event) => {
  event.preventDefault();
  runs += 1;
  runCount.textContent = `${runs} ${runs === 1 ? "run" : "runs"}`;
  try {
    const outcome = processToken(tokenInput.value);
    splitValue.textContent = `${outcome.prefix} · ${outcome.payload} · ${outcome.received}`;
    mapValue.textContent = outcome.scores.join(" · ");
    checkValue.textContent = `supplied ${outcome.received} / computed ${outcome.expected}`;
    setResult(outcome.valid ? "valid" : "invalid",
      outcome.valid ? "Toy check matched" : "Toy check did not match",
      outcome.valid ? "The callback ran once per payload character. Try the tampered sample next."
        : "The callback still ran; its computed check differs from the supplied one.");
  } catch (error) {
    splitValue.textContent = "—";
    mapValue.textContent = "—";
    checkValue.textContent = "—";
    setResult("invalid", "Could not process token", error.message);
  }
});
