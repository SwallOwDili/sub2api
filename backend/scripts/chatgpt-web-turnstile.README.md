# ChatGPT web image VM runner

The web image client follows `/backend-api/f/conversation`. When Sentinel requires
a VM challenge, configure a local runner using an argv JSON array:

```sh
export SUB2API_CHATGPT_WEB_TURNSTILE_COMMAND='["node","/absolute/path/to/sub2api/backend/scripts/chatgpt-web-turnstile.cjs"]'
```

The included runner requires Node.js and `jsdom`. It resolves `jsdom` from the
frontend workspace or the current working directory. Installing the frontend
development dependencies provides it in the local development environment.
The backend container does not automatically include this runtime.

The backend passes the challenge, requirements key, user agent, script URLs and
build identifier through stdin. It never passes account credentials to the
runner. The runner returns a JSON object containing `token` on stdout; the
backend forwards it in Sentinel finalize and the subsequent generation request.
Do not log stdin or stdout. Each invocation has a 15-second timeout.

The runner implements the inspected client's instruction VM in a JSDOM
environment. It does not open or control a logged-in browser. This compatibility
implementation is not a complete browser; upstream VM changes or browser-only
probes may require updating it. Failed or missing proofs produce an explicit
error instead of silently continuing without a required challenge.

Local verification on 2026-10-15 completed Sentinel, conversation prepare,
`/f/conversation`, asynchronous conversation polling and PNG download. This is
separate from the existing Codex Responses image route.
