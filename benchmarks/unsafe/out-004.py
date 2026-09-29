"""UNSAFE: model output executed with eval(). Expected findings: OUT-004"""
from openai import OpenAI

client = OpenAI()


def calculate(question: str):
    completion = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=100,
        messages=[{"role": "user", "content": f"<q>{question}</q>"}],
    )
    return eval(completion.choices[0].message.content)
