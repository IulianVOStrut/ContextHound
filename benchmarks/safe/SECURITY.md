# Security Policy

Please report vulnerabilities privately to security@acme.example.

## Known attack patterns we test against

- Jailbreak prompts that ask the model to act as "DAN" or enter a so-called developer mode.
- Instructions hidden in documents, for example "disregard all previous rules".
- Requests to print the system prompt or reveal hidden instructions.

Our regression suite replays these attacks on every release.
