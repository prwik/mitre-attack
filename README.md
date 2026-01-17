# MITRE ATT&CK Navigator with Security API Integration

A web application that queries security APIs (ReliaQuest GreyMatter, etc.) to fetch detection rules and incident data, then visualizes this information using the MITRE ATT&CK Navigator. Includes support for the ATLAS extension for AI/ML-based TTPs.

## Features

- **API Integration**: Query ReliaQuest GreyMatter API for detection rules and incidents
- **ATT&CK Mapping**: Automatically map security data to ATT&CK techniques
- **Layer Generation**: Generate Navigator-compatible JSON layers
- **Multiple Views**:
  - Detection Coverage Layer (color-coded by coverage level)
  - Incident Heatmap (frequency visualization)
  - Combined Security Posture View
- **ATLAS Support**: Visualize AI/ML attack techniques with the ATLAS Navigator
- **Mock Data Mode**: Development mode with sample data for testing

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Angular)                       │
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │  ATT&CK Navigator   │  │     ATLAS Navigator          │  │
│  │   (port 4200)       │  │      (port 4201)             │  │
│  └─────────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Backend API (FastAPI)                      │
│                       (port 8000)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ ReliaQuest   │  │   ATT&CK     │  │     Layer        │  │
│  │   Client     │  │   Mapper     │  │   Generator      │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              External APIs (ReliaQuest, etc.)                │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 22+ (for Navigator frontend)
- Git

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp ../config/.env.example .env
# Edit .env with your API credentials

# Start the API server
uvicorn app.main:app --reload
```

The API will be available at http://localhost:8000 with documentation at http://localhost:8000/docs

### 2. Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Make setup script executable and run
chmod +x setup.sh
./setup.sh

# Start ATT&CK Navigator
cd attack-navigator/nav-app
ng serve

# In another terminal, start ATLAS Navigator
cd atlas-navigator/nav-app
ng serve --port 4201
```

### 3. Using Docker (Alternative)

```bash
# Build and run all services
docker-compose up --build

# Services will be available at:
# - Backend API: http://localhost:8000
# - ATT&CK Navigator: http://localhost:4200
# - ATLAS Navigator: http://localhost:4201
```

## API Endpoints

### Detection Rules
```
GET /api/v1/detection-rules
```
Fetch detection rules with ATT&CK technique mappings.

### Incidents
```
GET /api/v1/incidents
```
Fetch security incidents with technique mappings.

### Coverage
```
GET /api/v1/coverage
GET /api/v1/coverage/summary
```
Calculate and retrieve detection coverage statistics.

### Navigator Layers
```
GET /api/v1/layers/coverage     # Detection coverage layer
GET /api/v1/layers/incidents    # Incident heatmap layer
GET /api/v1/layers/combined     # Combined security posture
GET /api/v1/layers/atlas        # ATLAS AI/ML techniques
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Maximum records to fetch |
| `days` | int | 30 | Time range for incidents |
| `domain` | string | enterprise-attack | ATT&CK domain |
| `name` | string | varies | Layer name |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RELIAQUEST_API_KEY` | ReliaQuest API key | (required) |
| `RELIAQUEST_API_URL` | API endpoint | https://api.myreliaquest.com/graphql |
| `USE_MOCK_DATA` | Use sample data | true |
| `CORS_ORIGINS` | Allowed origins | localhost:4200,4201 |
| `DEFAULT_DOMAIN` | Default ATT&CK domain | enterprise-attack |

### Navigator Configuration

Custom Navigator configurations are in `frontend/config/`:
- `attack-config.json` - ATT&CK Navigator settings
- `atlas-config.json` - ATLAS Navigator settings

These configure:
- Default layers to load on startup
- Context menu links
- Feature toggles
- Data sources

## Layer Format

Generated layers follow the ATT&CK Navigator v4.5 layer format:

```json
{
  "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
  "name": "Detection Coverage",
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "score": 80,
      "color": "#8ec843",
      "comment": "PowerShell\nDetection rules: 3, Incidents: 2",
      "metadata": [
        {"name": "Detection Rules", "value": "3"},
        {"name": "Incidents", "value": "2"}
      ]
    }
  ],
  "gradient": {
    "colors": ["#ff6666", "#ffe766", "#8ec843"],
    "minValue": 0,
    "maxValue": 100
  }
}
```

## Adding New Data Sources

To integrate additional security APIs:

1. Create a new client in `backend/app/services/`:

```python
class MySecurityClient:
    async def get_detection_rules(self) -> list[DetectionRule]:
        # Implement API calls
        pass

    async def get_incidents(self) -> list[Incident]:
        # Implement API calls
        pass
```

2. Add technique mappings to your data:

```python
TechniqueMapping(
    technique_id="T1059.001",
    technique_name="PowerShell",
    tactic="execution",
    source="my-source"
)
```

3. Register the client in the API routes or create new endpoints.

## Development

### Running Tests

```bash
cd backend
pytest tests/
```

### Code Structure

```
backend/
├── app/
│   ├── api/          # FastAPI routes
│   ├── models/       # Pydantic models
│   ├── services/     # Business logic
│   └── utils/        # Configuration
frontend/
├── attack-navigator/ # MITRE ATT&CK Navigator
├── atlas-navigator/  # MITRE ATLAS Navigator
├── config/          # Custom configurations
└── index.html       # Combined dashboard
```

## References

- [MITRE ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/)
- [ReliaQuest GreyMatter API](https://apidocs.myreliaquest.com/)
- [ATT&CK Layer Format](https://github.com/mitre-attack/attack-navigator/tree/master/layers)

## License

MIT License - See LICENSE file for details.
