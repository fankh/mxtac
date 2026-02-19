# MxTac App

MITRE ATT&CK security operations platform — FastAPI backend + React/TypeScript frontend.

## Quick Start

### Option A: Docker Compose (recommended)
```bash
docker-compose up
```
- Frontend: http://localhost:5173
- Backend API: http://localhost:8080
- API docs: http://localhost:8080/docs

### Option B: Manual

**Backend**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

## Structure
```
app/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/   # auth, overview, detections
│   │   ├── core/               # config, security (JWT)
│   │   ├── schemas/            # Pydantic models
│   │   └── services/           # mock_data
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── layout/         # Sidebar, TopBar
│       │   ├── shared/         # SeverityBadge, StatusPill
│       │   └── features/
│       │       ├── overview/   # KpiCards, Timeline, Heatmap, ...
│       │       └── detections/ # DetectionsPage, DetectionPanel
│       ├── lib/api.ts          # API client (axios)
│       └── types/api.ts        # TypeScript interfaces
└── docker-compose.yml
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Login (analyst@mxtac.local / mxtac2026) |
| GET | `/api/v1/overview/kpis` | Dashboard KPI metrics |
| GET | `/api/v1/overview/timeline` | 7-day detection timeline |
| GET | `/api/v1/overview/tactics` | Top ATT&CK tactics |
| GET | `/api/v1/overview/coverage/heatmap` | Coverage heatmap |
| GET | `/api/v1/overview/integrations` | Integration status |
| GET | `/api/v1/detections` | Paginated detections (filter + sort) |
| GET | `/api/v1/detections/{id}` | Detection detail |
| PATCH | `/api/v1/detections/{id}` | Update status/assignment |
