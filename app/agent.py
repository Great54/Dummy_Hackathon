import os

from dotenv import load_dotenv
from google import genai


# Load environment variables from .env
load_dotenv()

# Get Gemini API key
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError(
        "GEMINI_API_KEY is not set. "
        "Please check your .env file."
    )


# Create Gemini client
client = genai.Client(api_key=api_key)


def ask_gemini(user_prompt: str) -> str:
    """Send a prompt to Gemini and return the response."""

    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=user_prompt
    )

    return response.text


def main():
    print("\n===================================")
    print("       GEMINI AI ASSISTANT")
    print("===================================")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        user_prompt = input("You: ")

        if user_prompt.lower() in ["exit", "quit"]:
            print("\nGoodbye!")
            break

        if not user_prompt.strip():
            continue

        try:
            response = ask_gemini(user_prompt)

            print("\nGemini:")
            print(response)
            print()

        except Exception as e:
            print(f"\nError: {e}\n")


if __name__ == "__main__":
    main()