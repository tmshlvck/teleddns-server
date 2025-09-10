# Data Model Implementation Plan

This document outlines the changes needed to align the current teleddns-server data model with the requirements specified in SPECS.md.

## Current State Analysis

### Current Models (in `src/teleddns_server/model.py`)
- **User**: Basic user with username/password, is_admin flag
- **Server**: DNS master servers with API configuration
- **MasterZone**: DNS zones with SOA record fields
- **AccessRule**: Simple user-zone pattern-based authorization
- **RR Types**: A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV

### Current Authentication
- Basic password-only authentication using bcrypt
- No support for 2FA, PassKeys, or SSO
- No API bearer tokens

### Current Authorization
- Simple AccessRule table with user-zone-pattern relationships
- No group-based permissions
- No label-specific authorizations

## Required Changes

### 1. Authentication System Enhancement

#### 1.1 User Model Extensions
**Current**: `User(id, username, password, is_admin, created_at, updated_at)`

**New**: Add fields to support advanced authentication:
```python
class User(SQLModel, table=True):
    # Existing fields...
    email: Optional[str] = Field(unique=True)
    is_admin: bool = Field(default=False)  # Keep existing field

    # 2FA TOTP
    totp_secret: Optional[str] = Field(default=None)  # Base32 encoded secret
    totp_enabled: bool = Field(default=False)
    totp_backup_codes: Optional[str] = Field(default=None)  # JSON array of backup codes

    # SSO Integration
    sso_provider: Optional[str] = Field(default=None)  # "saml", etc.
    sso_subject_id: Optional[str] = Field(default=None)  # External user ID
    sso_enabled: bool = Field(default=False)

    # Account status
    is_active: bool = Field(default=True)
    last_login: Optional[datetime] = Field(default=None)

    # Relationships
    api_tokens: List["UserToken"] = Relationship(back_populates="user")
    group_memberships: List["UserGroup"] = Relationship(back_populates="user")
    user_label_authorizations: List["UserLabelAuthorization"] = Relationship(back_populates="user")
    owned_zones: List["MasterZone"] = Relationship(back_populates="owner")
```

#### 1.2 New Models for Authentication

**API Bearer Token Model**:
```python
class UserToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(unique=True)  # SHA-256 hash of the token
    description: Optional[str] = Field(default=None)
    user_id: int = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="api_tokens")

    expires_at: Optional[datetime] = Field(default=None)
    last_used: Optional[datetime] = Field(default=None)
    is_active: bool = Field(default=True)

    # Scopes for future API expansion
    scopes: Optional[str] = Field(default="*")  # JSON array of scopes

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)
```

**PassKey Support** (WebAuthn):
```python
class UserPassKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    user: User = Relationship()

    credential_id: str = Field(unique=True)  # Base64URL encoded
    public_key: str  # CBOR encoded public key
    sign_count: int = Field(default=0)

    name: Optional[str] = Field(default=None)  # User-friendly name
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = Field(default=None)
    is_active: bool = Field(default=True)
```

### 2. Authorization System (Groups + Label Authorizations)

#### 2.1 Group System
**Group Model**:
```python
class Group(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, min_length=2)
    description: Optional[str] = Field(default=None)

    # Relationships
    user_memberships: List["UserGroup"] = Relationship(back_populates="group")
    group_label_authorizations: List["GroupLabelAuthorization"] = Relationship(back_populates="group")
    owned_zones: List["MasterZone"] = Relationship(back_populates="group")

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)
```

**User-Group Relationship**:
```python
class UserGroup(SQLModel, table=True):
    user_id: int = Field(foreign_key="user.id", primary_key=True)
    group_id: int = Field(foreign_key="group.id", primary_key=True)

    user: User = Relationship(back_populates="group_memberships")
    group: Group = Relationship(back_populates="user_memberships")

    created_at: datetime = Field(default_factory=datetime.utcnow)
```

#### 2.2 Label Authorization System
Replace `AccessRule` with more granular authorization:

**User Label Authorization**:
```python
class UserLabelAuthorization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="user_label_authorizations")

    zone_id: int = Field(foreign_key="masterzone.id")
    zone: "MasterZone" = Relationship()

    label_pattern: str  # Regex pattern for allowed labels

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)
```

**Group Label Authorization**:
```python
class GroupLabelAuthorization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="group.id")
    group: Group = Relationship(back_populates="group_label_authorizations")

    zone_id: int = Field(foreign_key="masterzone.id")
    zone: "MasterZone" = Relationship()

    label_pattern: str  # Regex pattern for allowed labels

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)
```

### 3. Zone Model Updates

**Updated MasterZone Model**:
```python
class MasterZone(SQLModel, table=True):
    # Existing fields...

    # Owner and group assignment
    owner_id: int = Field(foreign_key="user.id")
    owner: User = Relationship(back_populates="zones")

    group_id: Optional[int] = Field(default=None, foreign_key="group.id")
    group: Optional[Group] = Relationship(back_populates="zones")

    # Remove old access_rules relationship
    # access_rules: List["AccessRule"] = Relationship(back_populates="zone")  # REMOVE

    # Backend sync tracking
    content_dirty: bool = Field(default=True)
    last_content_sync: Optional[datetime] = Field(default=None)
```

### 4. DNS Resource Record Types Enhancement

#### 4.1 Current RR Types Analysis
**Currently Implemented**: A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV

#### 4.2 Missing Common RR Types (RFC Compliance)
Add support for these essential DNS record types:

**Additional RR Types**:
```python
class SSHFP(RR, table=True):
    zone: MasterZone = Relationship()
    algorithm: int  # 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
    hash_type: int  # 1=SHA-1, 2=SHA-256
    fingerprint: str  # Hex string

class TLSA(RR, table=True):
    zone: MasterZone = Relationship()
    cert_usage: int  # 0-3
    selector: int    # 0-1
    matching_type: int  # 0-2
    cert_data: str   # Hex string

class DNSKEY(RR, table=True):
    zone: MasterZone = Relationship()
    flags: int
    protocol: int = Field(default=3)
    algorithm: int
    public_key: str  # Base64 encoded

class DS(RR, table=True):
    zone: MasterZone = Relationship()
    key_tag: int
    algorithm: int
    digest_type: int
    digest: str  # Hex string

class NAPTR(RR, table=True):
    zone: MasterZone = Relationship()
    order: int
    preference: int
    flags: str
    service: str
    regexp: str
    replacement: str
```

#### 4.3 Data Type Improvements
**Enhanced validation for existing types**:
- Improve DNS name validation regexes to be fully RFC-compliant
- Add proper IPv6 address validation
- Enhance TXT record validation for length limits
- Add CAA flag validation (0-255 range)

### 5. Server Model Updates

**Enhanced Server Model**:
```python
class Server(SQLModel, table=True):
    # Existing fields...

    # Server status tracking
    is_active: bool = Field(default=True)
    last_config_sync: Optional[datetime] = Field(default=None)
    config_dirty: bool = Field(default=True)

    # Sync monitoring
    last_sync_fail: Optional[datetime] = Field(default=None)
```

## Migration Strategy

### Phase 1: Authentication Enhancement
1. Add new User model fields with default values
2. Create UserToken model and table
3. Create UserPassKey model and table
4. Implement authentication middleware for bearer tokens
5. Add 2FA TOTP support
6. Add PassKey WebAuthn support

### Phase 2: Authorization System
1. Create Group model and table
2. Create UserGroup link table
3. Create UserLabelAuthorization and GroupLabelAuthorization tables
4. Migrate existing AccessRule data to new authorization tables
5. Update authorization logic in view.py
6. Drop AccessRule table

### Phase 3: DNS Records Enhancement
1. Add missing RR type models (SOA, SSHFP, TLSA, DNSKEY, DS, NAPTR)
2. Enhance validation for all RR types
3. Update zone file generation logic
4. Add DNS RFC compliance validation

### Phase 4: Zone and Server Improvements
1. Add owner_id and group_id to MasterZone
2. Add sync tracking fields
3. Update backend sync logic
4. Add health monitoring for servers

## Database Migration Scripts

Not needed. There is no running production instance so far.

## API Changes Required

### DDNS API Changes
- Support bearer token authentication alongside basic auth
- Enforce 2FA/PassKey users to use bearer tokens only
- Add IP address validation improvements

## Security Considerations

1. **Token Storage**: Store only SHA-256 hashes of API bearer tokens
2. **2FA Backup Codes**: Store hashed backup codes, generate 10 codes
3. **PassKey Storage**: Store public keys only, never private keys
4. **Session Security**: Implement proper session timeout and renewal
5. **Audit Logging**: Log all authentication and authorization events
6. **Rate Limiting**: Add rate limiting for authentication attempts

## Testing Requirements

1. **Unit Tests**: All new models and validation logic
2. **Integration Tests**: Authentication flows (password, 2FA, PassKey, SSO)
3. **API Tests**: All new REST endpoints
4. **Migration Tests**: Database migration scripts
5. **Security Tests**: Token handling, permission enforcement
6. **DDNS Tests**: Both basic auth and bearer token flows

## Configuration Updates

Add new settings to `settings.py`:
```python
class Settings(BaseSettings, cli_parse_args=True):
    # Existing settings...

    # Authentication
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # 2FA
    TOTP_ISSUER_NAME: str = "TeleDDNS"
    BACKUP_CODES_COUNT: int = 10

    # PassKeys
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "TeleDDNS Server"
    WEBAUTHN_ORIGIN: str = "http://localhost:8085"

    # Authorization
    DEFAULT_GROUP_NAME: str = "users"
```

This implementation plan provides a comprehensive upgrade path that maintains backward compatibility while adding all the required features specified in SPECS.md.
