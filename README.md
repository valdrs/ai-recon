# AI-Augmented Recon & Attack Surface Analyser

A proof-of-concept cybersecurity reconnaissance and attack surface analysis platform. It combines active reconnaissance enumeration with a Retrieval-Augmented Generation (RAG) architecture powered by FAISS, mapping vulnerabilities directly to MITRE ATT&CK techniques, generating actionable remediation advice, and enforcing strict prompt injection defenses.

## Features
- **Attack Surface Enumeration:** Modular DNS, network port/service, and web/HTTP header scanners.
- **Secure AI Guardrails:** Input sanitization layer to defend against indirect prompt injection attacks embedded in HTTP banners or DNS TXT records.
- **RAG Architecture with FAISS:** Contextual enrichment using embedded security knowledge base (CVE summaries, OWASP Top 10, MITRE ATT&CK matrices).
- **AI-Assisted Risk Synthesis:** Executive risk scoring, automated MITRE technique mapping, and step-by-step remediation advice (supports Google Gemini, OpenAI, and out-of-the-box Mock/Local Fallback).
- **Premium Dark-Mode Dashboard:** Modern glassmorphism web interface built with HTML5, vanilla CSS, and JavaScript.

## Directory Structure
```
ai recon/
├── app/
│   ├── config.py             # Settings & LLM provider management
│   ├── models/               # Pydantic v2 schemas
│   ├── recon/                # Modular scanners (DNS, Port, Web)
│   ├── security/             # Prompt injection defense & sanitization
│   ├── rag/                  # FAISS vector store & knowledge base
│   ├── ai/                   # LLM synthesis engine
│   └── api/                  # FastAPI REST endpoints
├── frontend/                 # Dark-mode Web UI
├── main.py                   # Server entry point
└── requirements.txt
```

## Quickstart
1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Set Environment Variables (Optional):**
   ```bash
   # For Google Gemini (or leave unset for Mock/Testing mode)
   set GEMINI_API_KEY=your_api_key
   # Or for OpenAI
   set OPENAI_API_KEY=your_api_key
   ```
3. **Run the Server:**
   ```bash
   python main.py
   ```
4. **Access the Dashboard:**
   Open `http://localhost:8000` in your web browser.
