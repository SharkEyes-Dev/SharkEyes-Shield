import re
import logging
from fastapi import Request, status, FastAPI
from fastapi.responses import JSONResponse
from config import BAD_PATHS, MAX_FILE_SIZE

logger = logging.getLogger("sharkeyes_shield")
app = FastAPI()

BAD_PATHS = tuple(BAD_PATHS)

BAD_USER_AGENTS = [
    "curl", "wget", "python", "go-http-client", "java", "libwww", "aiohttp", 
    "httpx", "guzzle", "okhttp", "node-fetch", "axios",
    "nmap", "sqlmap", "nikto", "dirbuster", "dirsearch", "owasp", "zap", 
    "hydra", "w3af", "acunetix", "nessus",
    "headlesschrome", "phantomjs", "jsdom", "selenium", "puppeteer", "playwright",
    "mj12bot", "ahrefsbot", "semrushbot", "dotbot", "petalbot", "rogerbot"
]

AGENT_REGEX = re.compile("|".join(map(re.escape, BAD_USER_AGENTS)), re.IGNORECASE)

REASON = "You have been blocked by SharkEyes Shield Lite"


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