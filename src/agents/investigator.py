import json
import re
import ollama
from src.config import AI_MODEL_NAME
from src.agents.prompts import (
    SYSTEM_PROMPT, ANALYSIS_TEMPLATE, FINAL_CONCLUSION_PROMPT, TRUST_CLASSIFICATION_PROMPT 
)

class AIInvestigator:
    def __init__(self, model_name=AI_MODEL_NAME):
        self.model = model_name

    def _chat_with_retry(self, messages, context_tag="General", retries=3):
        for i in range(retries):
            try:
                response = ollama.chat(model=self.model, messages=messages)
                return response['message']['content']
            except Exception as e:
                print(f"[!] Ollama Error ({context_tag}): {e}. Retrying...")
        return "{}"

    def _clean_and_parse_json(self, raw_text, context_tag="JSON_Parse"):
        try:
            clean_text = re.sub(r'//.*', '', raw_text)
            match = re.search(r'(\{.*\})', clean_text, re.DOTALL)
            json_str = match.group(1) if match else clean_text
            if "```json" in raw_text:
                json_str = raw_text.split("```json")[1].split("```")[0].strip()
                json_str = re.sub(r'//.*', '', json_str)
            return json.loads(json_str)
        except Exception:
            pass
        return {}

    def classify_trust(self, candidates):
        meta_list = [{"pid": c["pid"], "name": c["name"]} for c in candidates]
        json_str = json.dumps(meta_list, indent=2)
        prompt = TRUST_CLASSIFICATION_PROMPT.replace("<<JSON_DATA>>", json_str)
        raw = self._chat_with_retry([{"role": "system", "content": "JSON-only Trust Classifier."}, {"role": "user", "content": prompt}], "TrustClassification")
        result = self._clean_and_parse_json(raw, "TrustCheck")
        if isinstance(result, list): return {str(i.get("pid")): i for i in result}
        return result or {}

    def analyze_evidence(self, context_payload):
        tools_list = context_payload.get("available_tools", [])
        tools_str = "\n".join([f"- {t}" for t in tools_list])
        flat_context = {
            "PID": context_payload.get("pid"),
            "CONFIDENCE": context_payload.get("current_score"),
            "HISTORY_SUMMARY": context_payload.get("history_summary"),
            "AVAILABLE_TOOLS": tools_str
        }
        prompt_text = ANALYSIS_TEMPLATE \
            .replace("<<PID>>", str(flat_context["PID"])) \
            .replace("<<CONFIDENCE>>", str(flat_context["CONFIDENCE"])) \
            .replace("<<HISTORY_SUMMARY>>", str(flat_context["HISTORY_SUMMARY"])) \
            .replace("<<AVAILABLE_TOOLS>>", str(flat_context["AVAILABLE_TOOLS"]))

        raw_response = self._chat_with_retry([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt_text}], context_tag="AnalyzeEvidence")
        return self._clean_and_parse_json(raw_response, "Analysis")

    def generate_conclusion(self, conclusion_payload):
        locked_verdict = conclusion_payload.get("locked_verdict", "UNKNOWN")
        locked_score = conclusion_payload.get("locked_score", 0.0)
        prompt = FINAL_CONCLUSION_PROMPT.replace("<<LOCKED_VERDICT>>", locked_verdict).replace("<<LOCKED_SCORE>>", str(locked_score))
        json_input = json.dumps({"target": conclusion_payload["target"], "findings": conclusion_payload["findings_summary"]}, indent=2)
        prompt += f"\n\nINPUT DATA:\n{json_input}"
        raw = self._chat_with_retry([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}], "Conclusion")
        result = self._clean_and_parse_json(raw, "Conclusion")
        if isinstance(result, dict):
            result["final_verdict"] = locked_verdict
            result["confidence_score"] = locked_score
            return result
        return {"pid": conclusion_payload["target"]["pid"], "final_verdict": locked_verdict, "confidence_score": locked_score, "incident_narrative": "Report generation failed."}
