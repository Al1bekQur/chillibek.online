"""Opt-in frontend delivery by the existing protected app; fixed assets only."""
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, FileResponse

ROOT = Path(__file__).resolve().parents[1]
PAGES = {'/': 'index.html', '/index.html': 'index.html', '/admin.html': 'admin.html', '/kitchen.html': 'kitchen.html'}
ASSETS = {'restaurant-dom.js'} | {f'restaurant-{page}.{ext}' for page in ['index', 'admin', 'kitchen'] for ext in ['js', 'css']}


def load_html(name):
    return (ROOT / name).read_text(encoding='utf-8').replace(
        'data-api-base="https://kali.pythonanywhere.com/api"', 'data-api-base="/api"')


def frontend_router(settings):
    router = APIRouter()
    if settings.serve_frontend:
        for path, name in PAGES.items():
            def endpoint(filename):
                async def page():
                    return HTMLResponse(load_html(filename), headers={'Cache-Control': 'no-store'})
                return page
            router.add_api_route(path, endpoint(name), methods=['GET', 'HEAD'])

        for name in sorted(ASSETS):
            def asset_endpoint(filename):
                async def asset():
                    return FileResponse(ROOT / filename, headers={'Cache-Control': 'no-store'})
                return asset
            router.add_api_route('/' + name, asset_endpoint(name), methods=['GET', 'HEAD'])
    return router
