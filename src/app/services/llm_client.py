"""
llm_client.py

Shared LLM client with automatic Groq -> Gemini failover.

ARES uses this module as the single interface for LLM generation.

Provider order:
    1. Groq
    2. Gemini

API keys:
    GROQ_API_KEY
    GEMINI_API_KEY

Keys are loaded from the project's .env file.
"""

import os

from dotenv import load_dotenv


# Load environment variables from .env
load_dotenv()


# ---------------------------------------------------------------------------
# MODEL CONFIGURATION
# ---------------------------------------------------------------------------

GROQ_MODEL = "openai/gpt-oss-20b"
GEMINI_MODEL = "gemini-2.5-flash"


# ---------------------------------------------------------------------------
# GROQ
# ---------------------------------------------------------------------------

def _call_groq(
    prompt: str,
    system: str | None = None,
) -> str:
    """
    Generate a response using Groq.
    """

    from groq import Groq

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set in the environment."
        )

    client = Groq(
        api_key=api_key
    )

    messages = []

    if system:
        messages.append(
            {
                "role": "system",
                "content": system,
            }
        )

    messages.append(
        {
            "role": "user",
            "content": prompt,
        }
    )

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
    )

    if not response.choices:
        raise RuntimeError(
            "Groq returned no choices."
        )

    content = response.choices[0].message.content

    if not content:
        raise RuntimeError(
            "Groq returned an empty response."
        )

    return content.strip()


# ---------------------------------------------------------------------------
# GEMINI
# ---------------------------------------------------------------------------

def _call_gemini(
    prompt: str,
    system: str | None = None,
) -> str:
    """
    Generate a response using Google Gemini.
    """

    from google import genai
    from google.genai import types

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set in the environment."
        )

    client = genai.Client(api_key=api_key)

    config = None

    if system:
        config = types.GenerateContentConfig(
            system_instruction=system
        )

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=config,
    )

    text = getattr(response, "text", None)

    if not text:
        raise RuntimeError(
            "Gemini returned an empty response."
        )

    return text.strip()


# ---------------------------------------------------------------------------
# PUBLIC LLM INTERFACE
# ---------------------------------------------------------------------------

def generate(
    prompt: str,
    system: str | None = None,
) -> str:
    """
    Generate text using Groq with Gemini fallback.

    Groq is attempted first.

    If Groq fails for any reason, Gemini is attempted.

    If both providers fail, RuntimeError is raised.
    """

    groq_error = None

    # ---------------------------------------------------------------
    # Attempt 1: Groq
    # ---------------------------------------------------------------

    try:

        return _call_groq(
            prompt=prompt,
            system=system,
        )

    except Exception as error:

        groq_error = error

        print(
            f"[ARES] Groq failed: {error}"
        )

        print(
            "[ARES] Falling back to Gemini..."
        )

    # ---------------------------------------------------------------
    # Attempt 2: Gemini
    # ---------------------------------------------------------------

    try:

        return _call_gemini(
            prompt=prompt,
            system=system,
        )

    except Exception as gemini_error:

        print(
            f"[ARES] Gemini failed: {gemini_error}"
        )

        raise RuntimeError(
            "Both LLM providers failed. "
            f"Groq error: {groq_error!r} | "
            f"Gemini error: {gemini_error!r}"
        ) from gemini_error