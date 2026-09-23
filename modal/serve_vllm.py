"""agentbox: serve an open-weight model on Modal with vLLM (PLAN §2.5).

vLLM's OpenAI-compatible server behind a bearer token. The agentbox router
(LiteLLM) calls it as `[models.remote.<name>]`; the agent never sees the key.

Checked 2026-09-23 against the Modal vLLM example (`@app.server`,
`@modal.enter`) and vLLM 0.30.0 (`vllm serve --api-key`, env `VLLM_API_KEY`).
Nothing here was deployed by the agentbox build.

Setup
-----
1. Make a random key and store it twice: in Modal (for the server) and in
   agentbox (for the router only):

       KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
       modal secret create agentbox-vllm-key VLLM_API_KEY="$KEY"
       printf '%s\\n' "$KEY" | agentbox secret set <profile> MODAL_API_KEY --stdin
       unset KEY

   (`agentbox secret set <profile> MODAL_API_KEY` without `--stdin` asks with
   a hidden prompt.)

2. Deploy:

       modal deploy modal/serve_vllm.py

   Modal prints the server URL, for example
   `https://<workspace>--agentbox-vllm-server.modal.run` (some regions print
   a `...modal.direct` host). vLLM serves the OpenAI API under `/v1`.

3. Add the model to the profile (`~/.config/agentbox/profiles/<profile>.toml`):

       [models.remote.qwen-modal]
       api_base = "https://<workspace>--agentbox-vllm-server.modal.run/v1"
       key = "MODAL_API_KEY"          # delivered to the router only
       model = "qwen3-coder"          # SERVED_NAME below
       provider = "vllm"

   The router allowlist gets the api_base host name automatically (https,
   port 443 only).

4. Use it:

       agentbox up <profile>
       agentbox claude <profile> --model remote/qwen-modal
       agentbox codex <profile> --model remote/qwen-modal
       agentbox pi <profile> --model remote/qwen-modal

Cost: the GPU runs while requests arrive and for SCALEDOWN after the last
one. `modal app stop agentbox-vllm` stops it.
"""

import modal

APP_NAME = "agentbox-vllm"
# Pinned image (multi-arch index digest, looked up 2026-09-23).
VLLM_IMAGE = (
    "vllm/vllm-openai:v0.30.0"
    "@sha256:8a69ffad015f138d7170c4ddc429e230a3bc1c1719f67e14324749df200a4b90"
)
MODEL_NAME = "Qwen/Qwen3-Coder-30B-A3B-Instruct"
MODEL_REVISION = "b2cff646eb4bb1d68355c01b18ae02e7cf42d120"  # HF commit, pinned
SERVED_NAME = "qwen3-coder"
GPU = "H100:1"
PORT = 8000
MINUTES = 60
SCALEDOWN = 10 * MINUTES
SECRET_NAME = "agentbox-vllm-key"  # holds VLLM_API_KEY

image = modal.Image.from_registry(VLLM_IMAGE).entrypoint([])
hf_cache = modal.Volume.from_name("agentbox-hf-cache", create_if_missing=True)
vllm_cache = modal.Volume.from_name("agentbox-vllm-cache", create_if_missing=True)
app = modal.App(APP_NAME)


@app.server(
    image=image,
    gpu=GPU,
    port=PORT,
    secrets=[modal.Secret.from_name(SECRET_NAME, required_keys=["VLLM_API_KEY"])],
    volumes={"/root/.cache/huggingface": hf_cache, "/root/.cache/vllm": vllm_cache},
    scaledown_window=SCALEDOWN,
    startup_timeout=20 * MINUTES,
    target_concurrency=32,
    # No Modal proxy auth: vLLM itself checks `Authorization: Bearer
    # $VLLM_API_KEY` on every /v1 route (the router sends it).
    unauthenticated=True,
)
class Server:
    @modal.enter()
    def start(self):
        import os
        import subprocess

        if not os.environ.get("VLLM_API_KEY"):
            raise RuntimeError(f"Modal secret {SECRET_NAME} has no VLLM_API_KEY")
        # The key stays in the env (vLLM reads VLLM_API_KEY): never in argv.
        cmd = [
            "vllm", "serve", MODEL_NAME,
            "--revision", MODEL_REVISION,
            "--served-model-name", SERVED_NAME,
            "--host", "0.0.0.0",
            "--port", str(PORT),
            "--max-model-len", "65536",
            "--enable-auto-tool-choice",
            "--tool-call-parser", "qwen3_coder",
            "--disable-fastapi-docs",
        ]  # fmt: skip
        self.process = subprocess.Popen(cmd)

    @modal.exit()
    def stop(self):
        self.process.terminate()
