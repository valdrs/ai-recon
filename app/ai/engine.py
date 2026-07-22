from __future__ import annotations
import json
import asyncio
from typing import Any, Dict, Optional
from app.config import settings, LLMProvider


class LLMEngine:
    """Unified LLM execution engine supporting Gemini, OpenAI, and intelligent Mock mode."""

    @classmethod
    async def generate_json(cls, system_prompt: str, user_prompt: str, mock_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Invoke the active LLM provider and return parsed JSON response."""
        provider = settings.get_active_provider()

        if provider == LLMProvider.GEMINI and settings.GEMINI_API_KEY:
            try:
                from google import genai
                from google.genai import types

                client = genai.Client(api_key=settings.GEMINI_API_KEY)
                # Run synchronous genai SDK call in executor for async compatibility
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: client.models.generate_content(
                        model=settings.GEMINI_MODEL,
                        contents=f"{system_prompt}\n\nUser Input:\n{user_prompt}",
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.2
                        )
                    )
                )
                return json.loads(response.text)
            except Exception as e:
                print(f"[WARN] Gemini API call failed ({e}). Falling back to Intelligent Mock Synthesis.")

        elif provider == LLMProvider.OPENAI and settings.OPENAI_API_KEY:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
                resp = await client.chat.completions.create(
                    model=settings.OPENAI_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2
                )
                return json.loads(resp.choices[0].message.content)
            except Exception as e:
                print(f"[WARN] OpenAI API call failed ({e}). Falling back to Intelligent Mock Synthesis.")

        # Default / Fallback: Intelligent Mock Engine
        return cls._generate_mock_synthesis(mock_data or {})

    @classmethod
    def _generate_mock_synthesis(cls, mock_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate high-fidelity, context-aware synthesis based on real sanitized findings and RAG citations."""
        target = mock_context.get("target", "target.local")
        findings = mock_context.get("findings", [])
        citations_map = mock_context.get("citations", {})

        vulnerabilities = []
        highest_cvss = 0.0

        for idx, f in enumerate(findings):
            f_id = f.get("finding_id", f"item-{idx}")
            title = f.get("title", "Unknown Discovery")
            desc = f.get("description", "")
            port = f.get("port")
            clean_ev = f.get("evidence_clean", "")
            cits = citations_map.get(f_id, [])

            # Extract matching MITRE citations
            mitre_mappings = []
            for c in cits:
                if c.get("category") == "MITRE_ATTACK":
                    mitre_mappings.append({
                        "technique_id": c["doc_id"].replace("MITRE-", ""),
                        "technique_name": c["title"].split(": ", 1)[-1] if ": " in c["title"] else c["title"],
                        "tactic": c.get("tactic", "Initial Access"),
                        "description": f"Mapped via RAG citation ({round(c['similarity_score']*100)}% match): {c['content'][:140]}..."
                    })

            # Determine severity and CVSS estimation based on port and type
            if port == 22 or "OpenSSH" in clean_ev or "regreSSHion" in clean_ev:
                severity = "Critical"
                cvss = 8.5
                impact = "Potential unauthenticated remote code execution or unauthorized shell access via exposed SSH service."
                remediation = [
                    "Upgrade OpenSSH to version 9.8p1 immediately.",
                    "Enforce strict public-key authentication (`PasswordAuthentication no` in `/etc/ssh/sshd_config`).",
                    "Restrict port 22 access using perimeter firewall or VPN IP whitelisting."
                ]
            elif port == 6379 or "Redis" in title or "NOAUTH" in clean_ev:
                severity = "Critical"
                cvss = 9.8
                impact = "Unauthenticated public Redis exposure allows arbitrary command execution, database dump reading, and SSH key injection."
                remediation = [
                    "Bind Redis service strictly to `127.0.0.1` inside `redis.conf`.",
                    "Configure mandatory authentication password (`requirepass`).",
                    "Block TCP port 6379 at corporate security gateway."
                ]
            elif port == 8080 or "Tomcat" in clean_ev:
                severity = "High"
                cvss = 7.8
                impact = "Exposed administration portal allows unauthorized WAR file deployment leading to web application compromise."
                remediation = [
                    "Restrict access to `/manager` web application to local administrative IP range via `context.xml`.",
                    "Change default credentials in `tomcat-users.xml`.",
                    "Implement HTTPS/TLS encryption for administrative endpoints."
                ]
            elif "Header" in title or "Missing" in title:
                severity = "Medium"
                cvss = 5.3
                impact = "Missing HTTP security headers increases susceptibility to Cross-Site Scripting (XSS), Clickjacking, and SSL stripping."
                remediation = [
                    "Implement `Strict-Transport-Security` (`HSTS`) header with `max-age=31536000`.",
                    "Define a strict `Content-Security-Policy` (`default-src 'self'`).",
                    "Configure `X-Frame-Options: DENY` to prevent UI redressing."
                ]
            elif "Subdomain" in title or "DNS" in title:
                severity = "Medium"
                cvss = 5.0
                impact = "Exposed subdomains (`admin`, `staging`, `api`) expand the public attack surface and may expose non-hardened legacy endpoints."
                remediation = [
                    "Audit DNS zone files and decommission stale or legacy subdomains.",
                    "Enforce Zero-Trust Network Access (ZTNA) or corporate SSO for internal admin subdomains."
                ]
            else:
                severity = "Low"
                cvss = 3.5
                impact = "Information disclosure provides adversaries with architectural insight during initial reconnaissance."
                remediation = ["Ensure software version tokens are hidden (`server_tokens off` in Nginx)."]

            if not mitre_mappings:
                mitre_mappings.append({
                    "technique_id": "T1190" if port in [80, 443, 8080] else "T1046",
                    "technique_name": "Exploit Public-Facing Application" if port in [80, 443, 8080] else "Network Service Discovery",
                    "tactic": "Initial Access" if port in [80, 443, 8080] else "Discovery",
                    "description": "Baseline MITRE ATT&CK technique mapped based on service discovery profile."
                })

            if cvss > highest_cvss:
                highest_cvss = cvss

            vulnerabilities.append({
                "vulnerability_id": f"vuln-{idx+1}",
                "title": title,
                "severity": severity,
                "cvss_estimate": cvss,
                "affected_service": f"{f.get('module', 'recon')}:{port or 'general'}",
                "description": desc or f"Discovered by {f.get('module', 'recon')} scanner.",
                "technical_impact": impact,
                "mitre_mappings": mitre_mappings,
                "rag_citations": cits,
                "remediation_steps": remediation
            })

        # Determine overall tier
        if highest_cvss >= 9.0:
            tier = "Critical"
        elif highest_cvss >= 7.0:
            tier = "High"
        elif highest_cvss >= 4.0:
            tier = "Medium"
        else:
            tier = "Low"

        return {
            "executive_summary": {
                "overall_risk_score": round(highest_cvss, 1),
                "risk_tier": tier,
                "summary_text": f"Reconnaissance analysis of {target} identified {len(vulnerabilities)} distinct security findings. The target currently exhibits a {tier.upper()} risk posture (Score: {highest_cvss}/10.0), primarily driven by exposed network services and missing defensive web configurations. Immediate prioritization should focus on hardening public-facing ports and neutralizing unauthenticated administrative access.",
                "key_attack_vectors": [
                    "Publicly Accessible SSH & Network Ports (TCP/22, TCP/6379, TCP/8080)",
                    "Subdomain & Administrative Endpoint Exposure (`admin.*`, `staging.*`)",
                    "Missing HTTP Hardening & Version Leakage"
                ],
                "critical_recommendations": [
                    "Immediately restrict TCP port 22 (SSH) and 6379 (Redis) access via firewall/VPN.",
                    "Audit and secure exposed internal administrative web portals (`admin.*`, Tomcat `/manager`).",
                    "Enforce strict HTTP security headers (`HSTS`, `CSP`) and suppress software version banners."
                ]
            },
            "vulnerabilities": vulnerabilities
        }


llm_engine = LLMEngine()
