# Token `scope` & `scopes` Claim Behaviour

This document describes how the `scope` and `scopes` JWT claims are populated in access tokens,
based on the combination of two tenant-level configuration properties.

---

## Configuration Properties

Both properties live under the **OAuth client** section of tenant configuration.

### 1. `oauth-scope-customization`

Enables scope/scopes bifurcation: `scope` = requested scopes, `scopes` = full assigned set.

| Surface | Exact key |
|---|---|
| **Default tenant properties file** | `tenant.props.default.client.oauth-scope-customization` |
| **Per-tenant properties file** | `tenants.profile.<TENANTID>.client.oauth-scope-customization` |
| **Environment variable (default tenant)** | `DEFAULT_TENANT_OAUTH_SCOPE_CUSTOMIZATION` |
| **Environment variable (per tenant)** | `tenants_profile_<TENANTID>_client_oauth-scope-customization` |
| **Type / Default** | Boolean / `false` |

### 2. `auth-code-scopeless-user-scopes`

When `true`, injects the user's full assigned scopes into the token when the token request
carries **no scope** (scopeless / portal user flow).  
Applies to `authorization_code` and `refresh_token` grant types **only**.

| Surface | Exact key |
|---|---|
| **Default tenant properties file** | `tenant.props.default.client.auth-code-scopeless-user-scopes` |
| **Per-tenant properties file** | `tenants.profile.<TENANTID>.client.auth-code-scopeless-user-scopes` |
| **Environment variable (default tenant)** | `DEFAULT_TENANT_AUTH_CODE_SCOPELESS_USER_SCOPES` |
| **Environment variable (per tenant)** | `tenants_profile_<TENANTID>_client_auth-code-scopeless-user-scopes` |
| **Type / Default** | Boolean / `false` |

> **Note on client type:**  
> A client registered with type `MULTI_ROLE_CLIENT` automatically activates the bifurcation
> path regardless of `oauth-scope-customization`. A client of any other type relies on
> `oauth-scope-customization` to decide the path.

---

## Grant Type: `authorization_code` (and `refresh_token`)

Claim population happens in two sequential steps.

---

### Step 1 — Scope pre-population (`auth-code-scopeless-user-scopes`)

`populateUserScopes()` is called **before** writing claims.

| `auth-code-scopeless-user-scopes` | Scopes in token request | User has scopes in user-management | Effective scopeSet going into Step 2 |
|---|---|---|---|
| `false` | any | any | Unchanged — original requested scopeSet |
| `true` | **empty / not sent** | **yes** | User's full assigned scopes (from user-management) |
| `true` | **empty / not sent** | no | Unchanged — empty |
| `true` | not empty | any | Unchanged — original requested scopeSet (only enriches when request is scopeless) |

---

### Step 2 — Claim writing (`oauth-scope-customization` / client type)

#### Path A — Single Role Client **and** `oauth-scope-customization = false`

Both `scope` and `scopes` are set identically to the effective scopeSet from Step 1.

| Effective scopeSet | `scope` claim | `scopes` claim |
|---|---|---|
| not empty | space-delimited scopeSet | scopeSet (array) |
| empty | _(claim not set)_ | _(claim not set)_ |

---

#### Path B — `MULTI_ROLE_CLIENT` **or** `oauth-scope-customization = true`

| Client registered scopes | Effective scopeSet (Step 1) | User scopes (user-management) | `scope` claim | `scopes` claim |
|---|---|---|---|---|
| empty | any | any | _(not set)_ | _(not set)_ |
| not empty | **empty** | any | all client scopes (space-delimited) | _(not set)_ |
| not empty | not empty | **empty** | scopeSet (space-delimited) | _(not set)_ |
| not empty | not empty | **not empty** | scopeSet (space-delimited) | user scopes (array) |

---

### Combined matrix — `authorization_code` / `refresh_token`

> **CC** = `oauth-scope-customization`, **SU** = `auth-code-scopeless-user-scopes`,  
> **MR** = client type is `MULTI_ROLE_CLIENT`,  
> **req** = scopes in token request, **U-scopes** = user's scopes in user-management,  
> **C-scopes** = client's registered scopes

| # | CC | SU | Client type | req scopes | U-scopes | `scope` claim | `scopes` claim |
|---|:---:|:---:|---|---|---|---|---|
| 1 | `false` | `false` | SINGLE_ROLE | `[A, B]` | `[A, B, C]` | `"A B"` | `[A, B]` |
| 2 | `false` | `false` | SINGLE_ROLE | _(empty)_ | `[A, B, C]` | _(not set)_ | _(not set)_ |
| 3 | `false` | `true` | SINGLE_ROLE | _(empty)_ | `[A, B, C]` | `"A B C"` | `[A, B, C]` |
| 4 | `false` | `true` | SINGLE_ROLE | `[A]` | `[A, B, C]` | `"A"` | `[A]` |
| 5 | `true` | `false` | any | `[A, B]` | `[A, B, C]` | `"A B"` | `[A, B, C]` |
| 6 | `true` | `false` | any | _(empty)_ | `[A, B, C]` | C-scopes (space-delimited) | _(not set)_ |
| 7 | `true` | `true` | any | _(empty)_ | `[A, B, C]` | `"A B C"` | `[A, B, C]` |
| 8 | `true` | `true` | any | `[A]` | `[A, B, C]` | `"A"` | `[A, B, C]` |
| 9 | `false` | `false` | MR | `[A, B]` | `[A, B, C]` | `"A B"` | `[A, B, C]` |
| 10 | `false` | `true` | MR | _(empty)_ | `[A, B, C]` | `"A B C"` | `[A, B, C]` |

---

## Grant Type: `client_credentials`

> `auth-code-scopeless-user-scopes` has **no effect** on this grant type.  
> Only `oauth-scope-customization` (or `MULTI_ROLE_CLIENT` type) matters.

---

### Path A — Single Role Client **and** `oauth-scope-customization = false`

| Requested scopes | `scope` claim | `scopes` claim |
|---|---|---|
| not empty | space-delimited requested scopes | requested scopes (array) |
| empty | _(not set)_ | _(not set)_ |

---

### Path B — `MULTI_ROLE_CLIENT` **or** `oauth-scope-customization = true`

| Client registered scopes | Requested scopes | `scope` claim | `scopes` claim |
|---|---|---|---|
| **empty** | any | _(not set)_ | _(not set)_ |
| not empty | **empty** | all client scopes (space-delimited) | all client scopes (array) |
| not empty | subset of client scopes | requested scopes (space-delimited) | all client scopes (array) |
| not empty | **not** a subset of client scopes | _(rejected upstream — token not issued)_ | — |

---

### Combined matrix — `client_credentials`

| # | CC | Client type | req scopes | C-scopes | `scope` claim | `scopes` claim |
|---|:---:|---|---|---|---|---|
| 1 | `false` | SINGLE_ROLE | `[A, B]` | `[A, B, C]` | `"A B"` | `[A, B]` |
| 2 | `false` | SINGLE_ROLE | _(empty)_ | `[A, B, C]` | _(not set)_ | _(not set)_ |
| 3 | `true` | any | _(empty)_ | `[A, B, C]` | `"A B C"` | `[A, B, C]` |
| 4 | `true` | any | `[A, B]` | `[A, B, C]` | `"A B"` | `[A, B, C]` |
| 5 | `true` | any | `[A, B]` | `[A, C]` | _(rejected upstream)_ | — |
| 6 | `true` | any | any | _(empty)_ | _(not set)_ | _(not set)_ |

---

## Decision Flow Diagram

```
Token Request
     │
     ├─── grant_type = client_credentials ──────────────────────────────────────────────────────────┐
     │                                                                                               │
     └─── grant_type = authorization_code / refresh_token                                           │
                  │                                                                                  │
                  ▼                                                                                  │
     ┌─ auth-code-scopeless-user-scopes = true ?                                                    │
     │  AND requested scope is empty ?                                                               │
     │  AND user has scopes in user-management ?                                                     │
     │           │                                                                                   │
     │          YES → scopeSet = user's assigned scopes from user-management                        │
     │           │                                                                                   │
     │          NO  → scopeSet = original requested scopes (may be empty)                           │
     └─────────────────────────────────────────────────────────────────────────────────────────────  │
                  │                                                                                  │
                  ▼ (both grant types converge here)                                               ◄─┘
     ┌─ MULTI_ROLE_CLIENT  OR  oauth-scope-customization = true ?
     │           │
     │          NO  ──► Single Role path
     │                   scope  = scopeSet (space-delimited)
     │                   scopes = scopeSet (array)
     │
     │          YES ──► Multi Role path
     │                   ├── client_credentials
     │                   │     scope  = requested scopes  (fallback: all client scopes if empty)
     │                   │     scopes = all client registered scopes
     │                   │
     │                   └── authorization_code / refresh_token
     │                         scope  = scopeSet  (fallback: all client scopes if empty)
     │                         scopes = user's assigned scopes from user-management (if any)
     └──────────────────────────────────────────────────────────────────────────────────────────────
```

---

## Property Reference

### Default tenant (`tenant-default.properties`)

```properties
tenant.props.default.client.oauth-scope-customization=${DEFAULT_TENANT_OAUTH_SCOPE_CUSTOMIZATION:false}
tenant.props.default.client.auth-code-scopeless-user-scopes=${DEFAULT_TENANT_AUTH_CODE_SCOPELESS_USER_SCOPES:false}
```

### Per-tenant properties file (`tenant-<TENANTID>.properties`)

```properties
tenants.profile.<TENANTID>.client.oauth-scope-customization=${<TENANTID_UPPER>_TENANT_OAUTH_SCOPE_CUSTOMIZATION:false}
tenants.profile.<TENANTID>.client.auth-code-scopeless-user-scopes=${<TENANTID_UPPER>_TENANT_AUTH_CODE_SCOPELESS_USER_SCOPES:false}
```

**Example — `ecsp` tenant (`tenant-ecsp.properties`):**

```properties
tenants.profile.ecsp.client.oauth-scope-customization=${ECSP_TENANT_OAUTH_SCOPE_CUSTOMIZATION:false}
tenants.profile.ecsp.client.auth-code-scopeless-user-scopes=${ECSP_TENANT_AUTH_CODE_SCOPELESS_USER_SCOPES:false}
```

### Environment variables / Spring Boot config override

| Property | Default tenant env var | Per-tenant env var |
|---|---|---|
| `oauth-scope-customization` | `DEFAULT_TENANT_OAUTH_SCOPE_CUSTOMIZATION` | `tenants_profile_<TENANTID>_client_oauth-scope-customization` |
| `auth-code-scopeless-user-scopes` | `DEFAULT_TENANT_AUTH_CODE_SCOPELESS_USER_SCOPES` | `tenants_profile_<TENANTID>_client_auth-code-scopeless-user-scopes` |

**Example — `ecsp` tenant via environment variable:**

```
tenants_profile_ecsp_client_oauth-scope-customization=true
tenants_profile_ecsp_client_auth-code-scopeless-user-scopes=true
```
