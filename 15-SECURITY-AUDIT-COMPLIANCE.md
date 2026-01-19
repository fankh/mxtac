# MxTac - Security Audit & Compliance

> **Document Type**: Security Compliance
> **Based on**: security-requirements.xlsx
> **Checklist Type**: Korean Enterprise Security Audit (설계-검수단계 보안성검토)
> **Date**: 2026-01-19
> **Total Requirements**: 25 security controls
> **Status**: Implemented in docs 01, 12, 13

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Requirements Analysis](#2-requirements-analysis)
3. [Gap Analysis vs Current Architecture](#3-gap-analysis-vs-current-architecture)
4. [Implementation Plan](#4-implementation-plan)
5. [Architecture Integration](#5-architecture-integration)
6. [Implementation Roadmap](#6-implementation-roadmap)
7. [Compliance Mapping](#7-compliance-mapping)

---

## 1. Executive Summary

### Overview

The security requirements checklist contains **25 security controls** across **6 categories**:

| Category | Requirements | Status |
|----------|--------------|--------|
| **계정관리 (Account Management)** | 3 | Review needed |
| **비밀번호관리 (Password Management)** | 6 | Partial compliance |
| **접근통제 (Access Control)** | 8 | Needs enhancement |
| **암호화 (Encryption)** | 2 | Compliant |
| **로그관리 (Log Management)** | 3 | Needs implementation |
| **운영관리 (Operations Management)** | 3 | N/A (SaaS) |

### Critical Findings

Based on the checklist, **11 out of 25 requirements** need implementation or enhancement:

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ **Y (Compliant)** | 8 | 32% |
| ❌ **N (Non-Compliant)** | 11 | 44% |
| ⚪ **NA (Not Applicable)** | 6 | 24% |

**Priority**: Address the 11 non-compliant items in MxTac architecture

---

## 2. Requirements Analysis

### 2.1 Account Management (계정관리)

#### REQ-1: Disable Default/Predictable Accounts
**Korean**: 추측 가능한 계정명을 변경하였는가?
**Status**: ✅ Y
**Current**: No predictable account names

**MxTac Implementation**:
```python
# backend/app/core/auth/account_validator.py
FORBIDDEN_USERNAMES = [
    'admin', 'administrator', 'root', 'system', 'test',
    'user', 'demo', 'guest', 'operator', 'mxtac'
]

def validate_username(username: str) -> bool:
    """Prevent predictable usernames"""
    if username.lower() in FORBIDDEN_USERNAMES:
        raise ValueError("Username is predictable and not allowed")
    return True
```

#### REQ-2: One Account Per Person (No Shared Accounts)
**Korean**: 1인 1계정만 발급하고, 공용계정 사용을 금지하였는가?
**Status**: ✅ Y
**Current**: 1 person = 1 account

**MxTac Implementation**:
```python
# backend/app/models/user.py
class User(Base):
    __tablename__ = "users"

    id = Column(UUID, primary_key=True, default=uuid4)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    employee_id = Column(String(50), unique=True)  # Enforce 1:1 mapping
    is_shared_account = Column(Boolean, default=False)  # Flag, requires approval

    __table_args__ = (
        Index('idx_employee_id', 'employee_id', unique=True),
    )
```

#### REQ-3: Auto-Lock Accounts After 3 Months Inactivity
**Korean**: 3개월이상 미사용 계정은 계정자동 잠금 기능을 적용하였는가?
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**
**Gap**: No automatic account locking based on inactivity

**MxTac Implementation**:
```python
# backend/app/services/account_lifecycle.py
from datetime import datetime, timedelta
from sqlalchemy import select

class AccountLifecycleService:
    async def auto_lock_inactive_accounts(self):
        """Lock accounts inactive for 90+ days"""
        threshold = datetime.utcnow() - timedelta(days=90)

        query = select(User).where(
            User.last_login < threshold,
            User.is_active == True,
            User.is_locked == False
        )

        inactive_users = await self.db.execute(query)

        for user in inactive_users.scalars():
            user.is_locked = True
            user.locked_reason = "Inactive for 90+ days"
            user.locked_at = datetime.utcnow()

            # Log the action
            await self.audit_log.log(
                action="ACCOUNT_AUTO_LOCKED",
                user_id=user.id,
                reason="90_days_inactivity"
            )

            # Notify user via email
            await self.email.send_account_locked_notification(user.email)

        await self.db.commit()
        return len(inactive_users.all())

# Schedule as background task
# backend/app/tasks/scheduled.py
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()

@scheduler.scheduled_job('cron', hour=2, minute=0)  # Daily at 2 AM
async def daily_account_cleanup():
    service = AccountLifecycleService()
    locked_count = await service.auto_lock_inactive_accounts()
    logger.info(f"Auto-locked {locked_count} inactive accounts")
```

### 2.2 Password Management (비밀번호관리)

#### REQ-4: Password Complexity Requirements
**Korean**: 비밀번호 생성 기준을 준수하고 있는가? (3가지 조합 8자리 이상 또는 2가지 조합 10자리 이상)
**Status**: ❌ **N (NEEDS ENHANCEMENT)**
**Gap**: Only 8+ characters, no complexity rules

**MxTac Implementation**:
```python
# backend/app/core/auth/password_policy.py
import re
from typing import Tuple

class PasswordPolicy:
    MIN_LENGTH_3_TYPES = 8
    MIN_LENGTH_2_TYPES = 10

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Enforce password policy:
        - 3 character types + 8+ chars, OR
        - 2 character types + 10+ chars
        - No more than 3 consecutive identical characters
        """
        if not password:
            return False, "Password is required"

        # Check character types
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        char_types = sum([has_lowercase, has_uppercase, has_digit, has_special])

        # Rule 1: 3 types + 8 chars
        if char_types >= 3 and len(password) >= PasswordPolicy.MIN_LENGTH_3_TYPES:
            pass
        # Rule 2: 2 types + 10 chars
        elif char_types >= 2 and len(password) >= PasswordPolicy.MIN_LENGTH_2_TYPES:
            pass
        else:
            return False, "Password must be: (3 char types + 8 chars) OR (2 char types + 10 chars)"

        # Check for 4+ consecutive identical characters
        if re.search(r'(.)\1{3,}', password):
            return False, "Password cannot have 4+ consecutive identical characters"

        return True, "Password meets requirements"

# FastAPI endpoint validation
from pydantic import validator

class UserCreate(BaseModel):
    email: EmailStr
    password: str

    @validator('password')
    def validate_password_strength(cls, v):
        valid, message = PasswordPolicy.validate_password(v)
        if not valid:
            raise ValueError(message)
        return v
```

#### REQ-5: Password Expiration (90 days) & History
**Korean**: 비밀번호 변경 기준을 준수하고 있는가? (분기별 변경, 이전 비밀번호 재사용 금지)
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**
**Gap**: No password expiration or history tracking

**MxTac Implementation**:
```python
# backend/app/models/user.py
class User(Base):
    __tablename__ = "users"

    id = Column(UUID, primary_key=True)
    email = Column(String(255), unique=True)
    password_hash = Column(String(255))
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    password_expires_at = Column(DateTime)  # NEW
    must_change_password = Column(Boolean, default=False)  # NEW

    # Relationship to password history
    password_history = relationship("PasswordHistory", back_populates="user")

class PasswordHistory(Base):
    __tablename__ = "password_history"

    id = Column(UUID, primary_key=True, default=uuid4)
    user_id = Column(UUID, ForeignKey('users.id'))
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="password_history")

    __table_args__ = (
        Index('idx_user_password_history', 'user_id', 'created_at'),
    )

# backend/app/services/password_service.py
from passlib.hash import bcrypt

class PasswordService:
    PASSWORD_EXPIRY_DAYS = 90
    PASSWORD_HISTORY_COUNT = 2  # Don't reuse last 2 passwords

    async def change_password(self, user: User, new_password: str):
        """Change user password with history check"""
        # Validate password strength
        valid, message = PasswordPolicy.validate_password(new_password)
        if not valid:
            raise ValueError(message)

        # Check against password history
        new_hash = bcrypt.hash(new_password)

        recent_passwords = await self.db.execute(
            select(PasswordHistory)
            .where(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(self.PASSWORD_HISTORY_COUNT)
        )

        for old_pwd in recent_passwords.scalars():
            if bcrypt.verify(new_password, old_pwd.password_hash):
                raise ValueError(
                    f"Cannot reuse last {self.PASSWORD_HISTORY_COUNT} passwords"
                )

        # Save current password to history
        history_entry = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash
        )
        self.db.add(history_entry)

        # Update user password
        user.password_hash = new_hash
        user.password_changed_at = datetime.utcnow()
        user.password_expires_at = datetime.utcnow() + timedelta(
            days=self.PASSWORD_EXPIRY_DAYS
        )
        user.must_change_password = False

        await self.db.commit()

        # Log password change
        await self.audit_log.log(
            action="PASSWORD_CHANGED",
            user_id=user.id,
            metadata={"method": "user_initiated"}
        )

# Middleware to enforce password expiration
# backend/app/api/dependencies.py
async def check_password_expiration(user: User = Depends(get_current_user)):
    if user.password_expires_at and user.password_expires_at < datetime.utcnow():
        user.must_change_password = True
        raise HTTPException(
            status_code=403,
            detail="Password expired. Please change your password."
        )
    return user
```

#### REQ-6: Password Failure Limit (5 attempts)
**Korean**: 비밀번호 실패횟수 제한을 설정하였는가?
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**
**Gap**: No failed login attempt tracking/lockout

**MxTac Implementation**:
```python
# backend/app/models/user.py
class User(Base):
    __tablename__ = "users"

    # ... existing fields ...
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

# backend/app/core/auth/login.py
class LoginService:
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30

    async def authenticate(self, email: str, password: str) -> User:
        """Authenticate user with failed attempt tracking"""
        user = await self.get_user_by_email(email)

        if not user:
            # Don't reveal if user exists
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = (user.locked_until - datetime.utcnow()).total_seconds() / 60
            raise HTTPException(
                status_code=403,
                detail=f"Account locked. Try again in {int(remaining)} minutes"
            )

        # Verify password
        if not bcrypt.verify(password, user.password_hash):
            # Increment failed attempts
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= self.MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=self.LOCKOUT_DURATION_MINUTES
                )

                await self.audit_log.log(
                    action="ACCOUNT_LOCKED",
                    user_id=user.id,
                    reason="MAX_FAILED_LOGIN_ATTEMPTS",
                    metadata={"attempts": user.failed_login_attempts}
                )

                await self.db.commit()

                raise HTTPException(
                    status_code=403,
                    detail=f"Account locked for {self.LOCKOUT_DURATION_MINUTES} minutes due to {self.MAX_FAILED_ATTEMPTS} failed attempts"
                )

            await self.db.commit()

            raise HTTPException(
                status_code=401,
                detail=f"Invalid credentials ({self.MAX_FAILED_ATTEMPTS - user.failed_login_attempts} attempts remaining)"
            )

        # Successful login - reset failed attempts
        if user.locked_until and user.locked_until < datetime.utcnow():
            user.locked_until = None

        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()

        await self.db.commit()

        return user
```

#### REQ-7: Force Password Change on First Login
**Korean**: 최초 또는 임시 비밀번호 부여 시 강제 변경하고 있는가?
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**

**MxTac Implementation**:
```python
# backend/app/api/endpoints/auth.py
@router.post("/login")
async def login(credentials: OAuth2PasswordRequestForm = Depends()):
    user = await auth_service.authenticate(
        credentials.username,
        credentials.password
    )

    # Check if password change required
    if user.must_change_password:
        # Return special token that only allows password change
        temp_token = create_temp_access_token(
            data={"sub": user.email, "temp": True}
        )
        return {
            "access_token": temp_token,
            "token_type": "bearer",
            "must_change_password": True,
            "message": "Password change required"
        }

    # Normal login
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/change-password-required")
async def change_initial_password(
    new_password: str,
    current_user: User = Depends(get_temp_user)
):
    """Force password change endpoint for initial/temp passwords"""
    await password_service.change_password(current_user, new_password)

    # Return normal token after password change
    access_token = create_access_token(data={"sub": current_user.email})
    return {"access_token": access_token, "token_type": "bearer"}
```

#### REQ-8: Random OTP/Auth Codes (N/A)
**Korean**: 추가적인 인증에 사용되는 인증번호는 무작위 추출값을 사용하는가?
**Status**: ⚪ NA (not using additional auth)

#### REQ-9: Password Masking
**Korean**: 비밀번호 입력 화면이 마스킹 처리 되어 있는가?
**Status**: ✅ Y (already implemented in frontend)

### 2.3 Access Control (접근통제)

#### REQ-10: Role-Based Access Control (RBAC)
**Korean**: 업무 Role에 맞게 접근권한이 부여할 수 있는가?
**Status**: ✅ Y (but needs enhancement)

**MxTac Implementation**:
```python
# backend/app/models/rbac.py
class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID, primary_key=True, default=uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    permissions = relationship("Permission", secondary="role_permissions")

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(UUID, primary_key=True, default=uuid4)
    resource = Column(String(100), nullable=False)  # alerts, rules, users
    action = Column(String(50), nullable=False)  # read, write, delete

    __table_args__ = (
        UniqueConstraint('resource', 'action', name='uq_resource_action'),
    )

class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(UUID, ForeignKey('roles.id'), primary_key=True)
    permission_id = Column(UUID, ForeignKey('permissions.id'), primary_key=True)

# Predefined roles
ROLES = {
    "viewer": ["alerts:read", "events:read", "dashboards:read"],
    "analyst": ["alerts:read", "alerts:write", "events:read", "investigations:write"],
    "hunter": ["alerts:*", "events:*", "queries:*", "hunts:*"],
    "engineer": ["rules:*", "connectors:*", "alerts:*"],
    "admin": ["*:*"]
}

# Permission decorator
from functools import wraps

def require_permission(resource: str, action: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            has_permission = await check_permission(
                current_user,
                resource,
                action
            )
            if not has_permission:
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission denied: {resource}:{action}"
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

# Usage
@router.post("/rules")
@require_permission("rules", "write")
async def create_rule(rule: RuleCreate, current_user: User):
    ...
```

#### REQ-11: Least Privilege Principle
**Korean**: 계정은 역할에 적합한 권한만을 부여하였는가?
**Status**: ❌ **N (same as REQ-10, needs granular permissions)**

#### REQ-12: IP Whitelisting for Admin Access
**Korean**: 운영자와 관리자 로그인 시 단말기 인증(IP, MAC 등) 방식을 적용 하였는가?
**Status**: ✅ Y (IP control available)

**MxTac Implementation**:
```python
# backend/app/models/user.py
class User(Base):
    __tablename__ = "users"

    # ... existing fields ...
    allowed_ip_ranges = Column(ARRAY(String))  # ['192.168.1.0/24', '10.0.0.5']

# Middleware
from ipaddress import ip_address, ip_network

async def check_ip_whitelist(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Enforce IP whitelisting for admin users"""
    if current_user.role.name in ['admin', 'engineer']:
        client_ip = request.client.host

        if current_user.allowed_ip_ranges:
            allowed = any(
                ip_address(client_ip) in ip_network(range_)
                for range_ in current_user.allowed_ip_ranges
            )

            if not allowed:
                await audit_log.log(
                    action="IP_ACCESS_DENIED",
                    user_id=current_user.id,
                    metadata={"client_ip": client_ip}
                )
                raise HTTPException(
                    status_code=403,
                    detail="Access denied from this IP address"
                )

    return current_user
```

#### REQ-13: Admin Panel Not Publicly Accessible
**Korean**: 관리자 페이지는 외부(인터넷)에 공개되지 않도록 하였는가?
**Status**: ❌ **N (needs IP restriction or 2FA)**

**MxTac Implementation**:
```yaml
# Kubernetes Ingress with IP whitelisting
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mxtac-admin
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "192.168.0.0/16,10.0.0.0/8"
spec:
  rules:
  - host: admin.mxtac.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: mxtac-admin-ui
            port:
              number: 80
```

#### REQ-14: Session Timeout (30 minutes)
**Korean**: 세션 차단(Session Timeout)을 적용하였는가?
**Status**: ✅ Y (60 min, needs to reduce to 30 min)

**MxTac Implementation**:
```python
# backend/app/core/auth/jwt.py
from datetime import datetime, timedelta
from jose import jwt

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Changed from 60 to 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return encoded_jwt

# Frontend: Auto-refresh token before expiration
# frontend/src/services/auth.ts
setInterval(async () => {
  const tokenExpiresAt = getTokenExpiration();
  const now = Date.now() / 1000;

  // Refresh if token expires in < 5 minutes
  if (tokenExpiresAt - now < 300) {
    await refreshToken();
  }
}, 60000); // Check every minute
```

#### REQ-15: Prevent Concurrent Sessions
**Korean**: 동일계정으로 2개 이상 동시 접속이 불가능하도록 설정하였는가?
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**

**MxTac Implementation**:
```python
# backend/app/core/auth/session.py
import redis.asyncio as redis

class SessionManager:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def create_session(self, user_id: str, token: str):
        """Create new session and invalidate old ones"""
        session_key = f"session:{user_id}"

        # Get existing session
        existing_token = await self.redis.get(session_key)

        if existing_token:
            # Add old token to blacklist
            await self.redis.setex(
                f"blacklist:{existing_token}",
                3600,  # 1 hour TTL
                "replaced_by_new_session"
            )

        # Store new session
        await self.redis.setex(
            session_key,
            1800,  # 30 minutes
            token
        )

    async def is_token_valid(self, token: str) -> bool:
        """Check if token is not blacklisted"""
        is_blacklisted = await self.redis.exists(f"blacklist:{token}")
        return not is_blacklisted

# Middleware
async def validate_session(
    request: Request,
    token: str = Depends(oauth2_scheme)
):
    """Validate that session is current"""
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = payload.get("sub")

    is_valid = await session_manager.is_token_valid(token)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Session invalidated. Please login again."
        )

    return user_id
```

#### REQ-16: Generic Login Error Messages
**Korean**: 로그인 실패 시 사유를 알 수 없도록 설계하였는가?
**Status**: ✅ Y (returns "Invalid credentials")

#### REQ-17: API Security (N/A)
**Korean**: 데이터 연동(API 연동) 시 보안대책을 적용하였는가?
**Status**: ⚪ NA (no data integration currently)

### 2.4 Encryption (암호화)

#### REQ-18: TLS Encryption (Disable TLS 1.0/1.1)
**Korean**: 통신구간 암호화 (TLS 1.2+)
**Status**: ✅ Y (but TLS 1.0/1.1 still enabled - **needs fix**)

**MxTac Implementation**:
```yaml
# kubernetes/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mxtac-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - mxtac.example.com
    secretName: mxtac-tls
  rules:
  - host: mxtac.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: mxtac-ui
            port:
              number: 80
```

#### REQ-19: Password Hashing (SHA-256+, better: bcrypt)
**Korean**: 비밀번호는 단방향 암호화를 적용하였는가?
**Status**: ✅ Y (using bcrypt, which is better than SHA-256)

**MxTac Implementation**:
```python
# backend/app/core/security.py
from passlib.context import CryptContext

# Use bcrypt with 12 rounds (secure for password hashing)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

def hash_password(password: str) -> str:
    """Hash password with bcrypt (better than SHA-256)"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return pwd_context.verify(plain_password, hashed_password)
```

### 2.5 Log Management (로그관리)

#### REQ-20: Login Activity Logging
**Korean**: 로그인 접속 이력을 로깅하고 있는가?
**Status**: ✅ Y (but needs verification)

**MxTac Implementation**:
```python
# backend/app/models/audit_log.py
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID, primary_key=True, default=uuid4)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(UUID, ForeignKey('users.id'), index=True)
    action = Column(String(100), nullable=False)  # LOGIN, LOGOUT, etc.
    ip_address = Column(String(45))  # IPv6-compatible
    user_agent = Column(Text)
    status = Column(String(20))  # SUCCESS, FAILURE
    reason = Column(String(255))  # Failure reason
    metadata = Column(JSON)

# backend/app/services/audit_service.py
class AuditService:
    async def log_login_attempt(
        self,
        user_id: Optional[UUID],
        email: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        reason: Optional[str] = None
    ):
        """Log all login attempts"""
        log_entry = AuditLog(
            user_id=user_id,
            action="LOGIN_ATTEMPT",
            ip_address=ip_address,
            user_agent=user_agent,
            status="SUCCESS" if success else "FAILURE",
            reason=reason,
            metadata={"email": email}
        )

        self.db.add(log_entry)
        await self.db.commit()
```

#### REQ-21: User Activity Logging
**Korean**: 시스템운영자 활동 내역을 로깅하고 있는가?
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**

**MxTac Implementation**:
```python
# Decorator for automatic activity logging
from functools import wraps

def log_activity(action: str, resource_type: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')

            # Execute the function
            result = await func(*args, **kwargs)

            # Log the activity
            await audit_service.log_activity(
                user_id=current_user.id,
                action=action,
                resource_type=resource_type,
                metadata={
                    "function": func.__name__,
                    "result": str(result)[:500]  # Truncate
                }
            )

            return result
        return wrapper
    return decorator

# Usage
@router.post("/rules")
@log_activity("CREATE", "rule")
async def create_rule(
    rule: RuleCreate,
    current_user: User = Depends(get_current_user)
):
    ...

@router.delete("/users/{user_id}")
@log_activity("DELETE", "user")
async def delete_user(
    user_id: UUID,
    current_user: User = Depends(get_current_admin)
):
    ...
```

#### REQ-22: Permission Change Logging
**Korean**: 접근권한 부여·변경·말소 내역을 로깅하고 있는가? (3년 보관)
**Status**: ❌ **N (NEEDS IMPLEMENTATION)**

**MxTac Implementation**:
```python
# backend/app/services/rbac_service.py
class RBACService:
    async def assign_role(self, user_id: UUID, role_id: UUID, assigned_by: UUID):
        """Assign role to user with logging"""
        user = await self.get_user(user_id)
        role = await self.get_role(role_id)

        old_role_id = user.role_id
        user.role_id = role_id

        await self.db.commit()

        # Log permission change
        await self.audit_log.log(
            action="ROLE_ASSIGNED",
            user_id=assigned_by,
            metadata={
                "target_user_id": str(user_id),
                "target_user_email": user.email,
                "old_role": str(old_role_id) if old_role_id else None,
                "new_role": str(role_id),
                "new_role_name": role.name
            }
        )

    async def revoke_role(self, user_id: UUID, revoked_by: UUID):
        """Revoke role from user"""
        user = await self.get_user(user_id)
        old_role = user.role

        user.role_id = None
        await self.db.commit()

        await self.audit_log.log(
            action="ROLE_REVOKED",
            user_id=revoked_by,
            metadata={
                "target_user_id": str(user_id),
                "revoked_role": old_role.name if old_role else None
            }
        )

# Retention policy: 3 years
# backend/app/tasks/scheduled.py
@scheduler.scheduled_job('cron', day=1, hour=3)  # Monthly
async def cleanup_old_audit_logs():
    """Keep audit logs for 3 years, archive older"""
    retention_date = datetime.utcnow() - timedelta(days=365 * 3)

    # Archive to S3/object storage
    old_logs = await db.execute(
        select(AuditLog).where(AuditLog.timestamp < retention_date)
    )

    # Export to JSON and upload
    # Then delete from database
```

### 2.6 Operations Management (운영관리)

#### REQ-23, 24, 25: Test Data & Patch Management
**Status**: ⚪ NA (SaaS service)

---

## 3. Gap Analysis vs Current Architecture

### 3.1 Compliance Status

| Requirement | Status | Priority | Effort |
|-------------|--------|----------|--------|
| REQ-3: Auto-lock inactive accounts (90 days) | ❌ N | **P0** | 3 days |
| REQ-4: Password complexity (3 types + 8 chars) | ❌ N | **P0** | 2 days |
| REQ-5: Password expiration (90 days) + history | ❌ N | **P0** | 5 days |
| REQ-6: Failed login limit (5 attempts) | ❌ N | **P0** | 3 days |
| REQ-7: Force password change on first login | ❌ N | **P0** | 2 days |
| REQ-10/11: Enhanced RBAC | ❌ N | P1 | 5 days |
| REQ-13: Admin panel IP restriction | ❌ N | **P0** | 1 day |
| REQ-14: Session timeout (30 min) | ⚠️ Partial | P1 | 1 day |
| REQ-15: Prevent concurrent sessions | ❌ N | P1 | 3 days |
| REQ-18: Disable TLS 1.0/1.1 | ⚠️ Partial | **P0** | 1 day |
| REQ-21: User activity logging | ❌ N | P1 | 4 days |
| REQ-22: Permission change logging | ❌ N | P1 | 3 days |

**Total Effort**: ~33 days (6-7 weeks with testing)

### 3.2 Architecture Changes Required

```
Current MxTac Architecture    →    Enhanced for Compliance
────────────────────────────        ─────────────────────────

┌─────────────────────┐             ┌─────────────────────┐
│   FastAPI Gateway   │             │   FastAPI Gateway   │
│                     │             │ + IP Whitelisting   │
│ - JWT Auth          │             │ + Session Manager   │
│ - Basic RBAC        │             │ + Activity Logger   │
└─────────────────────┘             └─────────────────────┘
         │                                   │
         ▼                                   ▼
┌─────────────────────┐             ┌─────────────────────┐
│    PostgreSQL       │             │    PostgreSQL       │
│                     │             │ + password_history  │
│ - users             │             │ + audit_logs (3yr)  │
│ - roles             │             │ + sessions          │
└─────────────────────┘             └─────────────────────┘
         │                                   │
         ▼                                   ▼
┌─────────────────────┐             ┌─────────────────────┐
│      Redis          │             │      Redis          │
│                     │             │ + session tracking  │
│ - Cache             │             │ + token blacklist   │
└─────────────────────┘             └─────────────────────┘
```

---

## 4. Implementation Plan

### 4.1 Phase 1: Critical Security Controls (P0 - Week 1-2)

**Goal**: Address 7 critical non-compliance items

#### Sprint Tasks

| Task | Days | Assignee | Deliverables |
|------|------|----------|--------------|
| Implement password complexity validation | 2 | Backend Dev | PasswordPolicy class, validators |
| Add password expiration (90 days) | 2 | Backend Dev | Password expiry logic, migration |
| Implement password history (no reuse last 2) | 1 | Backend Dev | PasswordHistory model |
| Add failed login attempt tracking + lockout | 3 | Backend Dev | LoginService with attempt tracking |
| Force password change on first login | 2 | Backend Dev | must_change_password flag, endpoint |
| Configure TLS 1.2+ only (disable 1.0/1.1) | 1 | DevOps | Nginx/Ingress config |
| Admin panel IP whitelisting | 1 | DevOps | Kubernetes Ingress annotations |

**Total**: 12 days

#### Acceptance Criteria

- ✅ Passwords must meet complexity rules (3 types + 8 chars OR 2 types + 10 chars)
- ✅ Password expires after 90 days, forced change
- ✅ Cannot reuse last 2 passwords
- ✅ Account locks after 5 failed login attempts for 30 minutes
- ✅ Initial/temp passwords must be changed on first login
- ✅ TLS 1.0 and 1.1 disabled, only 1.2+ accepted
- ✅ Admin panel accessible only from whitelisted IPs

### 4.2 Phase 2: Enhanced Access Control (P1 - Week 3-4)

**Goal**: Improve RBAC and session management

| Task | Days | Assignee | Deliverables |
|------|------|----------|--------------|
| Enhance RBAC with granular permissions | 5 | Backend Dev | Permission model, decorators |
| Implement session timeout (30 min) | 1 | Backend Dev | JWT expiry, frontend auto-refresh |
| Add concurrent session prevention | 3 | Backend Dev | SessionManager with Redis |
| Auto-lock inactive accounts (90 days) | 3 | Backend Dev | Scheduled task for cleanup |

**Total**: 12 days

### 4.3 Phase 3: Comprehensive Logging (P1 - Week 5-6)

**Goal**: Complete audit trail for compliance

| Task | Days | Assignee | Deliverables |
|------|------|----------|--------------|
| Implement user activity logging | 4 | Backend Dev | Activity log decorator, storage |
| Add permission change logging | 3 | Backend Dev | RBAC audit trail |
| Configure 3-year log retention | 2 | Backend Dev | Archive policy, cleanup task |
| Build audit log dashboard | 3 | Frontend Dev | UI for viewing audit logs |

**Total**: 12 days

---

## 5. Architecture Integration

### 5.1 Database Schema Changes

```sql
-- New tables for compliance

-- Password history
CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_user_password_history (user_id, created_at)
);

-- Enhanced users table
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP DEFAULT NOW();
ALTER TABLE users ADD COLUMN password_expires_at TIMESTAMP;
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMP;
ALTER TABLE users ADD COLUMN last_login TIMESTAMP;
ALTER TABLE users ADD COLUMN allowed_ip_ranges TEXT[];

-- Audit logs (3-year retention)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP DEFAULT NOW() NOT NULL,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20),
    reason VARCHAR(255),
    metadata JSONB,
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_user (user_id, timestamp),
    INDEX idx_audit_action (action, timestamp)
);

-- Create partition for audit logs (by year)
CREATE TABLE audit_logs_2026 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
```

### 5.2 Redis Schema

```python
# Session management
session:{user_id} → {token} (TTL: 30 min)
blacklist:{token} → "replaced_by_new_session" (TTL: 1 hour)

# Rate limiting (failed logins)
login_attempts:{user_id} → {count} (TTL: 30 min)
```

### 5.3 API Endpoints

```
POST   /api/v1/auth/login              # Enhanced with attempt tracking
POST   /api/v1/auth/change-password    # With history check
POST   /api/v1/auth/force-change       # First login password change
GET    /api/v1/audit/logs              # View audit trail
GET    /api/v1/audit/login-history     # Login history
GET    /api/v1/admin/inactive-accounts # 90+ day inactive users
POST   /api/v1/admin/lock-account      # Manual account lock
```

---

## 6. Implementation Roadmap

### Week-by-Week Plan

```
Week 1-2: Critical Security (P0)
├─ Day 1-2: Password complexity validation
├─ Day 3-4: Password expiration + history
├─ Day 5-7: Failed login tracking + lockout
├─ Day 8-9: Force password change on first login
├─ Day 10: TLS 1.2+ enforcement
├─ Day 11: Admin IP whitelisting
└─ Day 12: Testing + documentation

Week 3-4: Access Control Enhancement (P1)
├─ Day 1-5: Granular RBAC implementation
├─ Day 6: Session timeout (30 min)
├─ Day 7-9: Concurrent session prevention
├─ Day 10-12: Auto-lock inactive accounts
└─ Testing + integration

Week 5-6: Comprehensive Logging (P1)
├─ Day 1-4: User activity logging
├─ Day 5-7: Permission change logging
├─ Day 8-9: 3-year retention policy
├─ Day 10-12: Audit dashboard UI
└─ Testing + security review

Week 7: Final Testing & Documentation
├─ Penetration testing
├─ Compliance verification
├─ Documentation update
└─ Security review sign-off
```

### Milestone Deliverables

| Milestone | Week | Deliverables |
|-----------|------|--------------|
| **M1: Critical Security** | 2 | 7/7 P0 items completed, TLS hardened |
| **M2: Access Control** | 4 | Enhanced RBAC, session management |
| **M3: Audit Trail** | 6 | Complete logging, 3-year retention |
| **M4: Compliance Ready** | 7 | All 25 requirements addressed |

---

## 7. Compliance Mapping

### 7.1 Compliance Checklist

| # | Requirement | Implementation | Status | Week |
|---|-------------|----------------|--------|------|
| 1 | No predictable accounts | Account validator | ✅ Y | - |
| 2 | 1 person = 1 account | Employee ID unique constraint | ✅ Y | - |
| 3 | Auto-lock 90-day inactive | Scheduled task | ❌ → ✅ | 4 |
| 4 | Password complexity | PasswordPolicy class | ❌ → ✅ | 1 |
| 5 | Password expiration (90d) | Password service | ❌ → ✅ | 1 |
| 6 | Failed login limit (5x) | LoginService with tracking | ❌ → ✅ | 1 |
| 7 | Force initial password change | must_change_password flag | ❌ → ✅ | 2 |
| 8 | Random OTP | N/A | ⚪ NA | - |
| 9 | Password masking | Frontend input type=password | ✅ Y | - |
| 10 | Role-based access (RBAC) | Enhanced permission model | ⚠️ → ✅ | 3 |
| 11 | Least privilege | Same as #10 | ⚠️ → ✅ | 3 |
| 12 | IP whitelisting (admin) | Ingress + User.allowed_ips | ✅ Y | - |
| 13 | Admin not public | Ingress IP restriction | ❌ → ✅ | 2 |
| 14 | Session timeout (30 min) | JWT expiry | ⚠️ → ✅ | 3 |
| 15 | No concurrent sessions | SessionManager + Redis | ❌ → ✅ | 3 |
| 16 | Generic login errors | "Invalid credentials" | ✅ Y | - |
| 17 | API security | N/A | ⚪ NA | - |
| 18 | TLS 1.2+ only | Nginx config | ⚠️ → ✅ | 2 |
| 19 | Password hashing (bcrypt) | bcrypt with 12 rounds | ✅ Y | - |
| 20 | Login logging | AuditLog model | ✅ Y | - |
| 21 | Activity logging | Activity decorator | ❌ → ✅ | 5 |
| 22 | Permission change logging | RBAC audit | ❌ → ✅ | 5 |
| 23 | Test data anonymization | N/A | ⚪ NA | - |
| 24 | Delete test data | N/A | ⚪ NA | - |
| 25 | Latest version/patches | N/A (SaaS) | ⚪ NA | - |

**Final Compliance**: 25/25 (100%)
- ✅ Compliant: 8 items (already met)
- ❌ → ✅ Will be compliant: 11 items (to be implemented)
- ⚪ Not applicable: 6 items (SaaS, no external integration)

### 7.2 Testing Matrix

| Test Case | Expected Result | Verification Method |
|-----------|----------------|---------------------|
| Password <8 chars rejected | ❌ Error | Unit test |
| Password without 3 types rejected | ❌ Error | Unit test |
| Password same as previous 2 | ❌ Error | Integration test |
| 6 failed logins → locked | ✅ Locked 30 min | Integration test |
| First login forces password change | ✅ Redirected | E2E test |
| TLS 1.0 connection attempt | ❌ Refused | Security scan |
| Admin access from non-whitelisted IP | ❌ Denied | Integration test |
| 2 concurrent logins with same account | ❌ First session killed | Integration test |
| Account inactive 91 days | ✅ Auto-locked | Integration test |
| Login activity logged | ✅ In audit_logs | Integration test |
| Role change logged | ✅ In audit_logs | Integration test |

---

## 8. Summary & Recommendations

### 8.1 Implementation Summary

**Scope**: 11 non-compliant requirements to address
**Timeline**: 7 weeks (including testing)
**Effort**: ~36 developer-days
**Team**: 2 developers (1 backend, 1 frontend + DevOps)

### 8.2 Priority Recommendations

1. **Week 1-2 (Critical)**:
   - Implement password policy (complexity, expiration, history)
   - Add failed login tracking and account lockout
   - Disable TLS 1.0/1.1
   - IP-restrict admin panel

2. **Week 3-4 (High)**:
   - Enhance RBAC with granular permissions
   - Prevent concurrent sessions
   - Auto-lock inactive accounts

3. **Week 5-6 (Medium)**:
   - Comprehensive activity logging
   - 3-year audit trail retention
   - Audit dashboard UI

### 8.3 Success Criteria

✅ **Security Hardening**:
- All P0 security controls implemented
- TLS 1.2+ enforced
- Strong password policy (3 types + 8 chars)
- Account lockout after 5 failed attempts

✅ **Access Control**:
- Granular RBAC with per-resource permissions
- Session timeout (30 minutes)
- No concurrent sessions
- IP whitelisting for admin access

✅ **Audit & Compliance**:
- Complete audit trail (login, activity, permissions)
- 3-year log retention
- Audit dashboard for review

✅ **Testing**:
- 100% unit test coverage for new features
- Integration tests for all security controls
- Penetration testing passed
- Security review approved

---

*Security Requirements Implementation Plan*
*Created: 2026-01-19*
*Based on: security-requirements.xlsx (Korean Enterprise Security Audit)*
