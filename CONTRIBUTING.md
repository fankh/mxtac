# Contributing to MxTac

Thank you for your interest in contributing to MxTac! This document provides guidelines and information for contributors.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contribution Types](#contribution-types)
5. [Development Workflow](#development-workflow)
6. [Coding Standards](#coding-standards)
7. [Testing Guidelines](#testing-guidelines)
8. [Documentation](#documentation)
9. [Review Process](#review-process)
10. [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors. We expect everyone to:

- **Be respectful** - Treat everyone with respect and consideration
- **Be constructive** - Provide helpful feedback and suggestions
- **Be collaborative** - Work together toward common goals
- **Be patient** - Remember that everyone has different experience levels

### Unacceptable Behavior

- Harassment, discrimination, or personal attacks
- Trolling or inflammatory comments
- Publishing private information without consent
- Any conduct that would be inappropriate in a professional setting

### Reporting Issues

Report Code of Conduct violations to: conduct@mxtac.io

---

## Getting Started

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.11+ | Backend development |
| Node.js | 20 LTS | Frontend development |
| Docker | 24.0+ | Local development |
| Git | 2.40+ | Version control |

### Quick Start

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/mxtac.git
cd mxtac

# 3. Add upstream remote
git remote add upstream https://github.com/mxtac/mxtac.git

# 4. Create a branch for your work
git checkout -b feature/your-feature-name

# 5. Start development environment
docker-compose up -d

# 6. Make your changes and test

# 7. Submit a pull request
```

### Finding Issues to Work On

| Label | Description |
|-------|-------------|
| `good first issue` | Great for new contributors |
| `help wanted` | Community help needed |
| `bug` | Bug fixes |
| `enhancement` | New features |
| `documentation` | Documentation improvements |

Browse issues: https://github.com/mxtac/mxtac/issues

---

## Development Setup

### Backend Setup (Python)

```bash
# Create virtual environment
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run tests
pytest

# Start development server
uvicorn app.main:app --reload --port 8080
```

### Frontend Setup (React)

```bash
# Install dependencies
cd frontend
npm install

# Start development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### Docker Development

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Run specific service
docker-compose up -d api

# Rebuild after changes
docker-compose build api
docker-compose up -d api

# Stop all services
docker-compose down
```

### Environment Variables

```bash
# Copy example environment file
cp .env.example .env

# Edit with your settings
# Required variables:
# - DATABASE_URL
# - REDIS_URL
# - OPENSEARCH_URL
# - JWT_SECRET_KEY
```

---

## Contribution Types

### Bug Fixes

1. Search existing issues to avoid duplicates
2. Create an issue describing the bug
3. Reference the issue in your PR
4. Include tests that reproduce the bug

### New Features

1. Discuss in an issue before starting
2. Get approval from maintainers
3. Follow the design documents
4. Include tests and documentation

### Documentation

- Fix typos and improve clarity
- Add examples and use cases
- Translate to other languages
- Improve API documentation

### Integration Connectors

Creating a new connector:

```python
# backend/app/connectors/your_tool/connector.py

from app.connectors.base import BaseConnector

class YourToolConnector(BaseConnector):
    """Connector for YourTool integration."""
    
    name = "your_tool"
    version = "1.0.0"
    
    async def connect(self) -> bool:
        """Establish connection."""
        pass
    
    async def pull_events(self, since: datetime) -> AsyncIterator[RawEvent]:
        """Pull events from source."""
        pass
    
    async def push_action(self, action: ResponseAction) -> ActionResult:
        """Execute response action."""
        pass
    
    def get_ocsf_mapping(self) -> OCSFMapping:
        """Return OCSF field mapping."""
        pass
```

### Sigma Rules

Contributing Sigma rules:

```yaml
# rules/custom/your_rule.yml
title: Your Detection Rule
id: unique-uuid-here
status: experimental
description: Description of what this rule detects
author: Your Name
date: 2026/01/12
references:
    - https://reference.url
tags:
    - attack.tactic
    - attack.technique
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious_command'
    condition: selection
falsepositives:
    - Legitimate use case
level: medium
```

---

## Development Workflow

### Branch Naming

| Type | Format | Example |
|------|--------|---------|
| Feature | `feature/description` | `feature/prowler-connector` |
| Bug fix | `fix/description` | `fix/alert-deduplication` |
| Documentation | `docs/description` | `docs/api-examples` |
| Refactor | `refactor/description` | `refactor/sigma-engine` |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(connectors): add Prowler integration

- Implement ProwlerConnector class
- Add OCSF mapping for cloud findings
- Include unit tests

Closes #123
```

```
fix(sigma): handle empty detection conditions

Previously, rules with empty conditions caused a crash.
Now they are validated during rule loading.

Fixes #456
```

### Pull Request Process

1. **Create PR from your branch**
   - Use descriptive title
   - Fill out PR template
   - Link related issues

2. **PR Template:**

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring

## Related Issues
Fixes #123

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Added necessary documentation
- [ ] No new warnings
```

3. **Wait for review** (usually 24-48 hours)

4. **Address feedback** and push updates

5. **Merge** after approval

---

## Coding Standards

### Python (Backend)

**Style:**
- Follow PEP 8
- Use type hints
- Maximum line length: 88 characters (Black default)

**Tools:**
- **Ruff** - Linting
- **Black** - Formatting
- **mypy** - Type checking

**Example:**

```python
from typing import List, Optional
from datetime import datetime

from pydantic import BaseModel


class AlertCreate(BaseModel):
    """Schema for creating a new alert."""
    
    title: str
    description: Optional[str] = None
    severity: str
    technique_id: str


async def create_alert(
    alert_data: AlertCreate,
    user_id: str,
) -> Alert:
    """
    Create a new alert in the system.
    
    Args:
        alert_data: Alert creation data
        user_id: ID of the user creating the alert
        
    Returns:
        The created Alert object
        
    Raises:
        ValidationError: If alert data is invalid
    """
    # Implementation
    pass
```

### TypeScript (Frontend)

**Style:**
- Use TypeScript strict mode
- Prefer functional components
- Use named exports

**Tools:**
- **ESLint** - Linting
- **Prettier** - Formatting

**Example:**

```typescript
import { useState, useCallback } from 'react';
import type { Alert } from '@/types/alert';

interface AlertCardProps {
  alert: Alert;
  onAcknowledge: (id: string) => void;
}

export function AlertCard({ alert, onAcknowledge }: AlertCardProps) {
  const [isLoading, setIsLoading] = useState(false);

  const handleAcknowledge = useCallback(async () => {
    setIsLoading(true);
    try {
      await onAcknowledge(alert.id);
    } finally {
      setIsLoading(false);
    }
  }, [alert.id, onAcknowledge]);

  return (
    <div className="alert-card">
      <h3>{alert.title}</h3>
      <button onClick={handleAcknowledge} disabled={isLoading}>
        Acknowledge
      </button>
    </div>
  );
}
```

### SQL Migrations

```sql
-- migrations/001_create_alerts.sql
-- Description: Create alerts table
-- Author: Your Name
-- Date: 2026-01-12

CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Rollback:
-- DROP TABLE alerts;
```

---

## Testing Guidelines

### Test Requirements

| Type | Coverage Target | Required For |
|------|-----------------|--------------|
| Unit | 80%+ | All PRs |
| Integration | Key paths | Features |
| E2E | Critical flows | Releases |

### Python Tests

```python
# tests/test_sigma_engine.py

import pytest
from app.core.sigma_engine import SigmaEngine


@pytest.fixture
def sigma_engine():
    """Create a test SigmaEngine instance."""
    return SigmaEngine()


class TestSigmaEngine:
    """Tests for Sigma Engine."""
    
    def test_parse_valid_rule(self, sigma_engine):
        """Should parse a valid Sigma rule."""
        rule_yaml = """
        title: Test Rule
        logsource:
            category: test
        detection:
            selection:
                field: value
            condition: selection
        """
        rule = sigma_engine.parse_rule(rule_yaml)
        assert rule.title == "Test Rule"
    
    def test_parse_invalid_rule_raises_error(self, sigma_engine):
        """Should raise error for invalid rule."""
        invalid_yaml = "not: valid: yaml:"
        with pytest.raises(SigmaParseError):
            sigma_engine.parse_rule(invalid_yaml)
    
    @pytest.mark.asyncio
    async def test_evaluate_rule_matches(self, sigma_engine):
        """Should match event against rule."""
        # Setup
        rule = sigma_engine.parse_rule(SAMPLE_RULE)
        event = {"field": "value"}
        
        # Execute
        result = await sigma_engine.evaluate(event, rule)
        
        # Assert
        assert result.matched is True
```

### TypeScript Tests

```typescript
// src/components/AlertCard.test.tsx

import { render, screen, fireEvent } from '@testing-library/react';
import { AlertCard } from './AlertCard';

describe('AlertCard', () => {
  const mockAlert = {
    id: '123',
    title: 'Test Alert',
    severity: 'high',
  };

  it('renders alert title', () => {
    render(<AlertCard alert={mockAlert} onAcknowledge={jest.fn()} />);
    expect(screen.getByText('Test Alert')).toBeInTheDocument();
  });

  it('calls onAcknowledge when button clicked', async () => {
    const onAcknowledge = jest.fn();
    render(<AlertCard alert={mockAlert} onAcknowledge={onAcknowledge} />);
    
    fireEvent.click(screen.getByRole('button', { name: /acknowledge/i }));
    
    expect(onAcknowledge).toHaveBeenCalledWith('123');
  });
});
```

### Running Tests

```bash
# Backend
pytest                          # All tests
pytest tests/unit/              # Unit tests only
pytest --cov=app                # With coverage
pytest -k "test_sigma"          # Specific tests

# Frontend
npm test                        # All tests
npm test -- --watch             # Watch mode
npm test -- --coverage          # With coverage
```

---

## Documentation

### Code Documentation

**Python:**
```python
def calculate_coverage(techniques: List[str], rules: List[Rule]) -> float:
    """
    Calculate ATT&CK coverage percentage.
    
    Args:
        techniques: List of ATT&CK technique IDs
        rules: List of detection rules
        
    Returns:
        Coverage percentage as a float between 0 and 1
        
    Example:
        >>> coverage = calculate_coverage(['T1059', 'T1003'], rules)
        >>> print(f"Coverage: {coverage * 100}%")
        Coverage: 75.0%
    """
```

**TypeScript:**
```typescript
/**
 * Fetches alerts from the API with filtering.
 * 
 * @param filters - Filter parameters for the query
 * @param pagination - Pagination options
 * @returns Promise resolving to paginated alert list
 * 
 * @example
 * ```ts
 * const alerts = await fetchAlerts(
 *   { severity: 'critical' },
 *   { limit: 50, cursor: null }
 * );
 * ```
 */
export async function fetchAlerts(
  filters: AlertFilters,
  pagination: PaginationOptions
): Promise<PaginatedResponse<Alert>> {
  // Implementation
}
```

### Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | Project overview |
| `CONTRIBUTING.md` | This file |
| `docs/` | Detailed documentation |
| `docs/api/` | API documentation |
| `docs/guides/` | User guides |

### Building Documentation

```bash
# Build documentation site
cd docs
mkdocs build

# Serve locally
mkdocs serve

# Deploy (maintainers only)
mkdocs gh-deploy
```

---

## Review Process

### Review Criteria

| Area | Criteria |
|------|----------|
| **Code Quality** | Clean, readable, follows standards |
| **Tests** | Adequate coverage, passing |
| **Documentation** | Updated, clear |
| **Security** | No vulnerabilities introduced |
| **Performance** | No regressions |

### Review Checklist

For reviewers:

- [ ] Code is readable and follows conventions
- [ ] Tests are adequate and meaningful
- [ ] Documentation is updated
- [ ] No security issues
- [ ] Changes match the PR description
- [ ] Commit messages follow conventions

### Response Time

| Type | Expected Response |
|------|-------------------|
| First review | 24-48 hours |
| Follow-up | 24 hours |
| Critical fixes | Same day |

### Merge Requirements

- At least 1 approval from maintainer
- All CI checks passing
- No unresolved conversations
- Up-to-date with main branch

---

## Community

### Communication Channels

| Channel | Purpose |
|---------|---------|
| GitHub Issues | Bug reports, feature requests |
| GitHub Discussions | Questions, ideas |
| Discord | Real-time chat |
| Mailing List | Announcements |

### Getting Help

1. Check existing documentation
2. Search closed issues
3. Ask in GitHub Discussions
4. Join Discord for real-time help

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Annual contributor report

### Maintainers

| Role | Responsibility |
|------|----------------|
| Core Maintainer | Architecture, releases |
| Module Maintainer | Specific components |
| Community Manager | Community health |

---

## License

By contributing to MxTac, you agree that your contributions will be licensed under the Apache 2.0 License.

---

## Acknowledgments

Thank you to all our contributors! Your work makes MxTac better for everyone.

---

*Questions? Open an issue or reach out on Discord.*
