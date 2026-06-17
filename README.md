# SharkEyes Shield Lite 

A lightweight, high-performance middleware for FastAPI designed for basic web application protection (WAF). It filters simple malicious bots, blocks automated simple scanners, and enforces strict payload size limits at the application level.


## Features

* **Bot and Scanner Detection:** Instantly rejects requests from simple malicious parsers, automated quality control tools, and security scanners `(e.g., curl, selenium, sqlmap, ahrefs)` using a pre-compiled regular expression.

* **Header Validation:** Ensures the presence of User-Agent and Accept headers by checking the length of the User-Agent string.
* **Path Protection:** Blocks access to hidden files and known sensitive paths `(e.g., .env, wp-admin)`.
* **Payload Control:** Limits the maximum file size `(Content-Length)` for data modification methods `(POST, PUT, PATCH)`.

## Quick Start

### 1. Integration
Add the middleware to your FastAPI application:
Python
```python
from fastapi import FastAPI
from config import BAD_PATHS, MAX_FILE_SIZE

app = FastAPI()

def block_response(reason: str):
    logger.warning(f"Blocked request: {reason}")
    return JSONResponse(
        content={"detail": REASON}, status_code=status.HTTP_403_FORBIDDEN
    )


@app.middleware("http")
async def shakeyes_shield_lite(request: Request, call_next):
    user_agent = request.headers.get("user-agent", "")
    accept = request.headers.get("accept", "")

    if not accept or not user_agent:
        return block_response("Missing accept header or user agent ")
    
    if not (10 <= len(user_agent) <= 253):
        return block_response("Strange User Agent Length")
    
    if AGENT_REGEX.search(user_agent):
        return block_response("Blocked user agent")

    if request.url.path.startswith(BAD_PATHS):
        return block_response("Attempt to access bad path ")
    
    if request.method in ("PUT", "POST", "PATCH"):
        content_type = request.headers.get("content-type", "")
        content_length = request.headers.get("content-length", "")

        if not content_length or not content_type:
            return block_response("Missing content type or content ength")
        
        try:
            if int(content_length) > MAX_FILE_SIZE:
                return block_response("File size limit")
        except ValueError:
            return block_response("Bad type of content-length")
    return await call_next(request)

@app.get("/")
async def root(): 
    return {"message": "Secure Hello World"}
```

### Security Layout
[Client Request]  
│  
├──► [ Check Headers ] ───► Missing or Malformed? ──►403 Forbidden  
├──► [ Check Bot Regex ] ──► Matches Blacklist? ────► 403 Forbidden  
├──► [ Check Bad Path ] ──► Restricted Path? ─────► 403 Forbidden  
├──► [ Check Payload ] ───► Size > MAX_FILE_SIZE? ──►403 Forbidden  
│  
[ FastAPI Router ] (Request Safe) 

### Logs & Monitoring
The shield utilizes Python's built-in logging module. All blocked requests are logged with a WARNING level, providing the reason for the block, which can be easily piped into tools like ELK Stack, Grafana Loki, or Datadog.
License

[**Apache-2.0 license**](https://github.com/SharkEyes-Dev/SharkEyes-Shield?tab=Apache-2.0-1-ov-file)
