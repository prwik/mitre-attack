"""
MITRE ATT&CK Navigator API

A FastAPI backend that integrates with security tools (ReliaQuest, etc.)
to generate ATT&CK Navigator layers for threat visualization.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .api import router
from .api.routes import limiter
from .utils.config import get_settings

settings = get_settings()

# Configure logging
log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

openapi_tags = [
    {"name": "Health", "description": "Health check and status endpoints"},
    {"name": "Detection Rules", "description": "Detection rule management"},
    {"name": "Incidents", "description": "Incident data retrieval"},
    {"name": "Coverage", "description": "Detection coverage analysis"},
    {"name": "Layers", "description": "ATT&CK Navigator layer generation"},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    if settings.use_mock_data:
        logger.warning("Running with mock data - set USE_MOCK_DATA=false for production")
    yield
    logger.info("Shutting down application")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    API for generating MITRE ATT&CK Navigator layers from security tool data.

    ## Features
    - Fetch detection rules and incidents from ReliaQuest GreyMatter
    - Calculate detection coverage per ATT&CK technique
    - Generate Navigator-compatible JSON layers
    - Support for both ATT&CK and ATLAS frameworks

    ## Layer Types
    - **Coverage Layer**: Shows detection rule coverage
    - **Incident Layer**: Heatmap of incident frequency
    - **Combined Layer**: Both coverage and incidents
    - **ATLAS Layer**: AI/ML specific techniques
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    openapi_tags=openapi_tags,
)

# Configure rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix=settings.api_prefix)


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to API documentation."""
    return RedirectResponse(url="/docs")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
