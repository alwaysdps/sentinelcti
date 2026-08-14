"""HTTP layer.

Routers are grouped by responsibility. Authentication is not implemented in the
MVP, but every router is mounted through `api_router`, so adding a global
dependency later (e.g. `dependencies=[Depends(require_user)]`) is a one-line
change rather than an edit to every endpoint.
"""

from fastapi import APIRouter

from . import analyses, analyze, system

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(analyze.router)
api_router.include_router(analyses.router)

__all__ = ["api_router"]
