from openai import OpenAI

client = OpenAI()
MAX_ITERATIONS = 5
ALLOWED_TOOLS = {"get_weather"}


def run(messages):
    for _ in range(MAX_ITERATIONS):
        reply = client.chat.completions.create(model="gpt-4o", messages=messages, max_tokens=300)
        msg = reply.choices[0].message
        messages.append({"role": "assistant", "content": msg.content or ""})
        if not msg.tool_calls:
            return msg.content
        for call in msg.tool_calls:
            if call.function.name not in ALLOWED_TOOLS:
                raise ValueError("tool not allowed")
    return None
