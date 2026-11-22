# CyberShield AI — URL Scanner Demo

A beginner-friendly hackathon practice project using HTML, CSS, JavaScript, Python, and Flask. It checks URL text for a few explainable warning indicators. It does **not** visit submitted URLs or prove that a link is safe or unsafe.

## What each file does

- `app.py` starts the Flask website and exposes `POST /api/scan` for the browser.
- `url_checks.py` validates input and calculates a simple score with human-readable reasons. It only parses text locally; it makes no network requests.
- `message_checks.py` looks for pressure tactics, requests for credentials or payment, threats, and prize claims in pasted message text.
- `templates/index.html` contains the scanner page structure.
- `static/styles.css` controls the page colors, spacing, and responsive layout.
- `static/app.js` sends the form text to the local Flask endpoint and displays its response.
- `requirements.txt` lists the Python package to install.
- `.gitignore` keeps Python's virtual environment and generated files out of Git.

## Run on Windows (PowerShell)

1. Install Python 3.10 or newer and Visual Studio Code. In VS Code, open this project folder.
2. Open **Terminal → New Terminal** and run these commands from the project folder:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python app.py
   ```

3. If PowerShell blocks activation, use this for the current terminal only, then activate again:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

4. Open **http://127.0.0.1:5000** in your browser. Keep the terminal running while you use the app. Press **Ctrl+C** in that terminal to stop it.

## Try the API directly

With the app running, open a second PowerShell terminal and send a sample request:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/scan -Method Post -ContentType "application/json" -Body '{"url":"http://secure-login.example.com/account"}'
```

The response contains `risk_score` (0–100), `level`, `reasons`, and a `notice`. The score is a teaching aid based on a few visible URL patterns, not a trained AI model, reputation lookup, or definitive safety verdict. Attackers can evade these clues, and ordinary links can trigger them. Never enter private links or credentials into this demo.

## How the scan works

The browser sends the URL string to the local Flask app as JSON. Python checks its format and looks for indicators such as an IP address in place of a domain, `@` in the address, punycode, HTTP without HTTPS, a known shortener, many subdomain parts, an uncommon port, lure-like words, and unusually long text. Each indicator adds points and a reason. Flask returns JSON, and the browser displays it as text. No code calls the submitted address.

The message scanner sends pasted text and an optional URL to `POST /api/scan-combined`. Message wording and URL text receive separate scores, so they are easy to explain. Its phrase checks look for urgency, credential requests, payment language, threats, and prize claims. The URL checks are the same local checks used by the standalone URL scanner. Links are never opened. These scores are educational indicators, not proof of fraud or safety. The standalone `POST /api/scan-message` endpoint is also available for a message-only scan.
