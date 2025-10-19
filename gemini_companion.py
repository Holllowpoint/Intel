import requests
import json
import time
import base64
from typing import Dict, Any, Callable

# --- CONFIGURATION & API KEY ---
# The API Key provided by the user is integrated here.
GEMINI_API_KEY = "AIzaSyAGMmDbINJifkp2siEJXyMtG_cO6WV23ho"
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent"
MAX_RETRIES = 5

# Define the JSON schema for the AI's structured response.
# The AI MUST adhere to this structure for syllabus analysis.
SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "analysis_title": {"type": "STRING", "description": "A concise, actionable title for the analysis (e.g., 'Weekly Study Focus')."},
        "summary_of_context": {"type": "STRING", "description": "A 2-3 sentence summary of the provided syllabus context and user query."},
        "recommendations": {
            "type": "ARRAY",
            "description": "A list of 5 key, numbered recommendations or next steps based on the context.",
            "items": {"type": "STRING"}
        }
    },
    "required": ["analysis_title", "summary_of_context", "recommendations"],
    "propertyOrdering": ["analysis_title", "summary_of_context", "recommendations"]
}

# Define the system instruction to guide the AI's persona and task.
SYSTEM_INSTRUCTION = (
    "You are the 'Intelligent Study Companion AI'. Your task is to analyze the user's syllabus "
    "data and their specific question, then provide a structured, actionable analysis and "
    "set of recommendations. You must strictly adhere to the provided JSON schema and "
    "provide only the JSON object in your response."
)

class GeminiCompanion:
    """
    Handles structured communication with the Gemini API.
    """
    def __init__(self, api_key: str = GEMINI_API_KEY):
        self.api_key = api_key

    def _call_api(self, user_prompt: str) -> Dict[str, Any] | None:
        """Handles the API POST request with exponential backoff."""
        headers = {'Content-Type': 'application/json'}
        full_url = f"{API_URL}?key={self.api_key}"

        payload = {
            "contents": [{ "parts": [{"text": user_prompt}] }],
            "systemInstruction": { "parts": [{"text": SYSTEM_INSTRUCTION}] },
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": SCHEMA
            },
        }

        for attempt in range(MAX_RETRIES):
            try:
                response = requests.post(full_url, headers=headers, data=json.dumps(payload))
                response.raise_for_status()

                result = response.json()
                
                # Extract the JSON string from the response
                json_text = result['candidates'][0]['content']['parts'][0]['text']
                
                # Parse the JSON string into a Python dictionary
                parsed_json = json.loads(json_text)
                return parsed_json

            except requests.exceptions.RequestException as e:
                print(f"API Request failed: {e}")
                if attempt < MAX_RETRIES - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                else:
                    return {"analysis_title": "Error", "summary_of_context": "Failed to connect to the AI after multiple retries.", "recommendations": []}
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error processing AI response: {e}")
                return {"analysis_title": "Error", "summary_of_context": "The AI provided an invalid or malformed response structure.", "recommendations": []}
        return None

    def query(self, prompt: str, on_success: Callable, on_error: Callable):
        """
        Public method to query the AI, run in a separate thread by the GUI.

        Args:
            prompt: The full text prompt including context.
            on_success: Callback function for successful response handling.
            on_error: Callback function for error handling.
        """
        print(f"AI Companion running query...")
        try:
            structured_response = self._call_api(prompt)
            if structured_response:
                # Format the structured JSON into a readable string for the GUI
                formatted_response = self._format_response(structured_response)
                on_success(formatted_response)
            else:
                on_error("AI failed to generate a complete structured response.")
        except Exception as e:
            on_error(f"An unexpected error occurred during AI query: {str(e)}")

    def _format_response(self, idea: Dict[str, Any]) -> str:
        """Formats the structured dictionary into a clean string output."""
        output = "="*40 + "\n"
        output += f"AI ANALYSIS: {idea.get('analysis_title', 'N/A')}\n"
        output += "="*40 + "\n\n"

        output += "Summary of Context & Query:\n"
        output += f"  {idea.get('summary_of_context', 'No summary provided.')}\n\n"

        output += "Actionable Recommendations:\n"
        recommendations = idea.get('recommendations', [])
        if recommendations:
            for i, step in enumerate(recommendations, 1):
                output += f"  {i}. {step}\n"
        else:
            output += "  (No recommendations generated)\n"

        output += "\n" + "="*40
        return output
