import os
from fastapi import FastAPI
import uvicorn

app = FastAPI(title="RUACH Automations", version="2.0")


@app.get("/")
def read_root():
  return {
      "status": "online",
      "engine": "RUACH Automations v2",
      "message": "Cross-border compliance & e-invoicing engine ready.",
  }


@app.get("/health")
def health_check():
  return {"status": "healthy"}


if __name__ == "__main__":
  port = int(os.environ.get("PORT", 8080))
  uvicorn.run("app.main:app", host="0.0.0.0", port=port)
