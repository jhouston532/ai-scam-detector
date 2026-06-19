from ollama_interaction import prompt_ollama_stream as send_prompt
import json
import os
from datetime import datetime

def counsel(code: str, url: str) -> list[str]:
    
    model_list: list[str] = []
    results: list[str] = []
    for model in model_list:
        COUNSEL_PROMPT: str = """
            You are an expert code reviewer. 
            Your job is to analyze the provided code and determine whether the website it comes from is a scam or not. 

            Respond only with a JSON object defined as follows: 
            {
                "percentage": int
                "reasoning": string
            }

            Percentage should be a value between 0 and 100, representing the likelihood that the website is a scam.
            Reasoning should be a brief explanation of the factors that led to the percentage.

            Here is the code to analyze: {code}
            Here is the URL it comes from: {url}
        """

        results.append(send_prompt(COUNSEL_PROMPT.format(code=code, url=url), model))
    
    return results

def parse_results(results: list[str]) -> list[dict]:
    """Parse raw model responses into structured dicts, skipping malformed ones."""
    parsed = []
    for result in results:
        try:
            # Strip markdown code fences if the model wrapped its response
            clean = result.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            parsed.append(json.loads(clean))
        except json.JSONDecodeError:
            print(f"Warning: could not parse result: {result[:80]}...")
    return parsed


def aggregate(parsed: list[dict]) -> dict:
    """Average the percentages and collect all reasoning strings."""
    if not parsed:
        return {"average_percentage": None, "reasoning": []}
    avg = sum(p["percentage"] for p in parsed) / len(parsed)
    return {
        "average_percentage": round(avg, 1),
        "reasoning": [p["reasoning"] for p in parsed],
    }

def save_results(results: list[str], filename: str):
    """
    Parse, aggregate, and save results to a JSON file.
    Appends a timestamp to the filename to avoid overwrites.
    """
    parsed = parse_results(results)
    summary = aggregate(parsed)

    output = {
        "timestamp": datetime.now().isoformat(),
        "summary": summary,
        "raw_results": results,
        "parsed_results": parsed,
    }

    # Ensure output directory exists
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)

    # Append timestamp to avoid overwriting previous runs
    base, ext = os.path.splitext(filename)
    timestamped = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext or '.json'}"

    with open(timestamped, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to: {timestamped}")
    print(f"Average scam likelihood: {summary['average_percentage']}%")

    return timestamped