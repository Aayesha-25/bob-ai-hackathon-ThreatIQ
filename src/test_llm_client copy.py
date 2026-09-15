"""
test_llm_client.py — verify llm_client.generate() actually reaches a real
provider, before building anything on top of it.

Usage:
    python test_llm_client.py
"""

from app.services.llm_client import generate


def main():
    print("Testing llm_client.generate()...\n")

    try:
        result = generate(
            prompt="Reply with exactly one word: 'working'.",
            system="You are a terse test assistant.",
        )
        print("[PASS] Got a response:")
        print(f"    -> {result!r}")
        print("\nIf this says something like 'working', the client reached a real provider.")
    except RuntimeError as e:
        print("[FAIL] Both providers failed.")
        print(f"    -> {e}")
        print("\nCheck: is .env actually loaded? Are both keys valid? "
              "Try printing os.getenv('GROQ_API_KEY') to confirm it's not None.")
    except Exception as e:
        print(f"[FAIL] Unexpected error (not a provider failure — likely a bug): {e}")


if __name__ == "__main__":
    main()
