from fastapi import FastAPI

app = FastAPI(title="RUACH Automations", version="2.0")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "engine": "RUACH Automations v2",
        "message": "Cross-border compliance & e-invoicing engine ready."
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}
