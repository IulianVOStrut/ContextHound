# Acme Support Assistant

A small support chatbot for the Acme help centre.

## Setup

1. Copy `.env.example` to `.env` and set `OPENAI_API_KEY` to your API key.
2. Never commit your password, access token or private key to git.
3. Run `npm install` and then `npm start`.

## Configuration

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API key for the model provider |
| `DATABASE_PASSWORD` | Password for the internal database |
| `LOG_LEVEL` | Set to `debug` for verbose output |

## Troubleshooting

If the assistant stops responding, delete logs in `./tmp`, clear the cache and restart the service.
Developer mode can be enabled in the admin panel for local testing.

## Security

We treat all user messages as untrusted data. See `SECURITY.md` for how to report a vulnerability.
Our internal API lives at a private hostname and is never exposed to the model.
