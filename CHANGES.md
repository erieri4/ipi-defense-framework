# Project UI and Layer 1 Changes

## What was added
`frontend/` folder.

## Technology used
- `React`
- `Vite`
- plain `CSS`

The backend bridge for the frontend was built with:
- `FastAPI`
- `uvicorn`

The Layer 1 classifier uses:

- Hugging Face `transformers`
- model: `protectai/deberta-v3-base-prompt-injection`

## How to run
Run these two commands in separate terminals:

```powershell
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000
```

```powershell
cd frontend
npm run dev -- --host 127.0.0.1 --port 4173
```

Then open:

- `http://127.0.0.1:4173`

## Files added or changed

### New backend file

- `src/api.py`

File was added to expose a small API for the UI:

- `GET /health`
- `POST /validate`

## Existing files changed

### `src/layers/input_sanitizer.py`

This was extended from the original version.

Main changes:
- added structured analysis output instead of only returning a string
- added separate check results for:
  - regex validation
  - LLM classifier
- added graceful error handling when the model cannot load
- switched the classifier model to a public Hugging Face model that works in this environment

### `requirements.txt`

Added:

- `fastapi`
- `uvicorn`

These are needed so the React UI can call the Python layer through a small API server.

## What changed functionally from the original project

- the project has a React UI
- the UI calls the real Python Layer 1 through an API
- Layer 1 results are shown visually in the right-side panel
- regex and classifier results are shown separately
- the UI is already prepared to pass validated prompts to Layer 2 later

