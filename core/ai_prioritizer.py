import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


class AIPrioritizer:

    def __init__(self):

        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:

            raise Exception("OPENAI_API_KEY not found in .env")

        self.client = OpenAI(api_key=api_key)

    def score_host(self, services, vulnerabilities):

        prompt = f"""
You are an expert penetration tester.

Score this host from 0 to 100 based on exploitability.

Services:
{services}

Vulnerabilities:
{vulnerabilities}

Return only a number.
"""

        try:

            response = self.client.chat.completions.create(

                model="gpt-4o-mini",

                messages=[
                    {"role": "system", "content": "You are a penetration tester."},
                    {"role": "user", "content": prompt}
                ],

                temperature=0.2
            )

            score = response.choices[0].message.content.strip()

            return int(score)

        except Exception as e:

            print(f"[AI Error] {e}")

            return 0
