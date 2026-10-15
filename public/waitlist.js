"use strict";
// This preview has no approved encrypted transport. CSP also denies all network
// and native form submission. Never read, echo, persist, or log the address.
const form = document.getElementById("waitlist-form");
if (form) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    document.getElementById("form-status").textContent =
      "Collection is not open yet. No address was submitted.";
  });
}
