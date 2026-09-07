import os
import uvicorn
from backend.app.main import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    reload = os.environ.get("RELOAD", "false").lower() in ("true", "1", "yes")
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port, reload=reload)
