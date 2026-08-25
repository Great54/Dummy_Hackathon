import os

from dotenv import load_dotenv
from google import genai


# Load variables from .env
load_dotenv()

# Get Gemini API key
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError(
        "GEMINI_API_KEY is not set. "
        "Please add it to the .env file."
    )


# Create Gemini client
client = genai.Client(api_key=api_key)


# Send a test request to Gemini
response = client.models.generate_content(
    model="gemini-3.6-flash",
    contents="Explain Agentic AI in simple terms in 5 bullet points."
)


# Print Gemini's response
print("\n===== GEMINI RESPONSE =====\n")
print(response.text)
print("\n===========================\n")