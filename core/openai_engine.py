import os
from openai import OpenAI


class OpenAIEngine:

    def __init__(self, state):

        self.state = state

        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise Exception("OPENAI_API_KEY not set")

        self.client = OpenAI(api_key=api_key)

    def analyze(self):

        print("[*] OpenAI analyzing attack data")

        vulnerabilities = self.state.network.get("vulnerabilities", [])
        directories = self.state.network.get("directories", [])
        services = self.state.network.get("services", {})

        prompt = f"""
You are an expert penetration tester.

Target Information:
Services: {services}
Directories: {directories}
Vulnerabilities: {vulnerabilities}

Tasks:
1. Identify the best attack path
2. Explain why
3. Provide confidence score (0-100)
4. Recommend next step

Respond in JSON format:
{{
  "attack_path": "...",
  "reason": "...",
  "confidence": number,
  "next_step": "..."
}}
"""

        try:

            response = self.client.chat.completions.create(

                model="gpt-4o-mini",

                messages=[
                    {"role": "system", "content": "You are a professional penetration tester."},
                    {"role": "user", "content": prompt}
                ],

                temperature=0.2
            )

            result = response.choices[0].message.content

            self.state.ai_analysis = result

            print("[+] OpenAI analysis complete")

            return True

        except Exception as e:

            print(f"[!] OpenAI error: {e}")

            return False
