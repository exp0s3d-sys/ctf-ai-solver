# CTF AI Solver

An experimental command-line CTF analysis assistant that coordinates AI providers with a Docker-based Kali sandbox. It supports common challenge workflows across forensics, reverse engineering, cryptography, steganography, and web/pwn reconnaissance, then scans command output for likely flags.

## Requirements

- Python 3.10+
- Docker Desktop (or another Docker Engine)
- At least one API key from a supported provider: Groq, Cloudflare Workers AI, OpenRouter, DeepSeek, OpenAI, or Gemini

## Quick start

1. Install Python dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

2. Copy `.env.example` to `.env` and add your provider credentials. Keep `.env` private; it is ignored by Git.

3. Build the analysis image once:

   ```powershell
   python ctf_solver_v2.py --build
   ```

4. Put challenge files in `shared_workspace/`, then start the interactive menu:

   ```powershell
   python ctf_solver_v2.py
   ```

You can also launch the menu on Windows with `start.bat`. The tool writes generated reports under `reports/` and checkpoints under `ctf_state/`; those runtime files are excluded from Git.

## CLI examples

```powershell
python ctf_solver_v2.py --check
python ctf_solver_v2.py --all --flag "picoCTF{"
python ctf_solver_v2.py challenge-file --flag "flag{"
python ctf_solver_v2.py --url http://127.0.0.1:8080 --desc "local practice challenge"
```

File arguments refer to files inside `shared_workspace/`. Only use the web/pwn mode against systems you own or are authorized to test.

## Configuration

Set one or more provider keys in `.env` or your shell environment. Optional settings include `CTF_PROVIDERS`, provider model names, `CTF_PREFIX`, `CTF_STEPS`, `CTF_MEM`, and `CTF_CMD_TIMEOUT`. See the comments and configuration section in `ctf_solver_v2.py` for the full list.

## Project status

This is a personal, experimental project. Review the commands and sandbox configuration before using it with sensitive data or on a live target.
