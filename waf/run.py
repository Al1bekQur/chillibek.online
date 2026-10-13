import uvicorn

from .config import WAFSettings


if __name__ == "__main__":
    settings = WAFSettings()
    uvicorn.run(
        "waf.app:app",
        host=settings.listen_host,
        port=settings.listen_port,
        reload=False,
    )
