import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";

// The component was originally built as a Claude.ai artifact, which provides a
// built-in `window.storage` key-value API for persistence. That API doesn't exist
// in a normal browser, so we polyfill it here with localStorage — same interface,
// same behavior, so nothing in App.jsx needs to change.
if (!window.storage) {
  const ns = (key) => `alaga:${key}`;
  window.storage = {
    async get(key) {
      const value = localStorage.getItem(ns(key));
      if (value === null) return null;
      return { key, value };
    },
    async set(key, value) {
      localStorage.setItem(ns(key), value);
      return { key, value };
    },
    async delete(key) {
      const existed = localStorage.getItem(ns(key)) !== null;
      localStorage.removeItem(ns(key));
      return { key, deleted: existed };
    },
    async list(prefix = "") {
      const keys = Object.keys(localStorage)
        .filter((k) => k.startsWith(ns(prefix)))
        .map((k) => k.slice("alaga:".length));
      return { keys, prefix };
    },
  };
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
