# UIDAM Authorization Server – Properties Reference

---

## Table of Contents

1. [application.properties](#1-applicationproperties)
2. [Tenant Default Properties](#2-tenant-default-properties)

---

## Tenant Property Naming Convention

| File | Property prefix used in file | Equivalent ENV-variable convention |
|------|-------------------------------|-------------------------------------|
| `tenant-default.properties` | `tenant.props.default.<property>` | `DEFAULT_<PROPERTY>` |
| `tenant-<TENANTID>.properties` | `tenants.profile.<TENANTID>.<property>` | `<TENANTID>_<PROPERTY>` |

**Tenant property key convention:**  
`tenants_profile_<TENANTID>_<property-key>` where dots (`.`) are replaced with underscores (`_`) and hyphens (`-`) are kept as-is.

---

## 1. `application.properties`

### 1.1 Server & SSL

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `server.port` | `SPRING_AUTH_PROXY_PORT_HTTPS` | `9443` |
| `server.ssl.enabled` | `server_ssl_enabled` | `true` |
| `server.ssl.key-alias` | `KEYSTORE_ALIAS` | `uidam-dev` |
| `server.ssl.key-store-type` | `server_ssl_key-store-type` | `JKS` |
| `server.ssl.key-store` | `KEYSTORE_FILE_NAME` | `uidamauthserver.jks` |
| `server.ssl.key-store-password` | `KEYSTORE_PASS` | `uidam-test-pwd` |
| `server.http.port` | `SPRING_AUTH_PROXY_PORT` | `9000` |
| `server.servlet.session.timeout` | `server_servlet_session_timeout` | `5m` |
| `session.recreation.policy` | `session_recreation_policy` | `IF_REQUIRED` |

### 1.2 Application & Spring

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `spring.application.name` | `spring_application_name` | `uidam-authorization-server` |
| `spring.thymeleaf.enabled` | `spring_thymeleaf_enabled` | `true` |
| `spring.thymeleaf.prefix` | `UI_TEMPLATE_PATH` | `classpath:/templates/` |
| `spring.web.resources.static-locations` | `UI_STATIC_PATH` | `classpath:/static` |
| `spring.jpa.database-platform` | `spring_jpa_database-platform` | `org.hibernate.dialect.PostgreSQLDialect` |
| `spring.jpa.show-sql` | `spring_jpa_show-sql` | `false` |
| `spring.jpa.hibernate.ddl-auto` | `spring_jpa_hibernate_ddl-auto` | `none` |
| `spring.jpa.properties.hibernate.default_schema` | `UIDAM_DEFAULT_DB_SCHEMA` | `uidam` |
| `spring.main.allow-bean-definition-overriding` | `spring_main_allow-bean-definition-overriding` | `true` |
| `spring.profiles.active` | *(derived from `tenant.ids`)* | *(comma-separated list of active tenant IDs)* |

### 1.3 Database (Global / Liquibase)

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `postgres.jdbc.url` | `POSTGRES_DATASOURCE` | `jdbc:postgresql://localhost:5432/uidam_management` |
| `postgres.username` | `POSTGRES_USERNAME` | `ChangeMe` |
| `postgres.password` | `POSTGRES_PASSWORD` | `ChangeMe` |
| `postgres.driver.class.name` | `postgres_driver_class_name` | `org.postgresql.Driver` |
| `postgres.pool.name` | `postgres_pool_name` | `hikariConnectionPool` |
| `postgres.data-source-properties.cachePrepStmts` | `postgres_data_source_properties_cachePrepStmts` | `true` |
| `postgres.data-source-properties.prepStmtCacheSize` | `postgres_data_source_properties_prepStmtCacheSize` | `250` |
| `postgres.data-source-properties.prepStmtCacheSqlLimit` | `postgres_data_source_properties_prepStmtCacheSqlLimit` | `2048` |
| `postgres.max.idle.time` | `postgres_max_idle_time` | `0` |
| `postgres.min.pool.size` | `postgres_min_pool_size` | `15` |
| `postgres.max.pool.size` | `postgres_max_pool_size` | `30` |
| `postgres.connection.timeout.ms` | `postgres_connection_timeout_ms` | `60000` |
| `postgres.expected99thPercentileMs` | `postgres_expected99thPercentileMs` | `60000` |
| `postgres.datasource.create.retry.count` | `postgres_create_retry_count` | `3` |
| `postgres.datasource.retry.delay.ms` | `postgres_retry_delay` | `30` |
| `postgresdb.metrics.enabled` | `postgresdb_metrics_enabled` | `false` |
| `postgresdb.metrics.executor.shutdown.buffer.ms` | `postgresdb_metrics_executor_shutdown_buffer_ms` | `2000` |
| `postgresdb.metrics.thread.freq.ms` | `postgresdb_metrics_thread_freq_ms` | `5000` |
| `postgresdb.metrics.thread.initial.delay.ms` | `postgresdb_metrics_thread_initial_delay_ms` | `2000` |
| `uidam.default.db.schema` | `UIDAM_DEFAULT_DB_SCHEMA` | `uidam` |
| `spring.liquibase.enabled` | `spring_liquibase_enabled` | `true` |
| `uidam.liquibase.change-log.path` | `uidam_liquibase_change-log_path` | `classpath:database.schema/master.xml` |
| `uidam.liquibase.db.credential.global` | `UIDAM_LIQUIBASE_DB_CREDENTIAL_GLOBAL` | `true` |

### 1.4 OAuth2 / Issuer

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `ignite.oauth2.issuer.host` | `SPRING_AUTH_PROXY_HOSTNAME` | `localhost:9443` |
| `ignite.oauth2.issuer.prefix` | `SPRING_AUTH_PROXY_PREFIX` | *(empty)* |
| `ignite.oauth2.issuer.protocol` | `ignite_oauth2_issuer_protocol` | `https` |
| `ignite.oauth2.jks-enabled` | `JKS_ENABLED` | `true` |
| `uidam.oauth2.token.hash.algorithm` | `UIDAM_OAUTH2_TOKEN_HASH_ALGORITHM` | `SHA-256` |
| `uidam.oauth2.token.hash.salt` | `UIDAM_OAUTH2_TOKEN_HASH_SALT` | `ChangeMe` |
| `security.client.bcrypt.strength` | `SECURITY_CLIENT_BCRYPT_STRENGTH` | `high` |
| `user.management.base.url` | `USER_MANAGEMENT_ENV` | `http://localhost:8080` |
| `user.session.force.login` | `user_session_force_login` | `true` |

### 1.5 Tenant Configuration

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `tenant.default-tenant-id` | `TENANT_DEFAULT` | `<TENANT_ID>` |
| `tenant.default` | `TENANT_DEFAULT` | `<TENANT_ID>` |
| `tenant.multitenant.enabled` | `TENANT_MULTITENANT_ENABLED` | `false` |
| `tenant.ids` | `TENANT_IDS` | `<TENANT_ID1>,<TENANT_ID2>,...` |
| `tenant.config.validation.enabled` | `TENANT_CONFIG_VALIDATION_ENABLED` | `true` |
| `uidam.tenant.config.dbname.validation` | `UIDAM_TENANT_CONFIG_DBNAME_VALIDATION` | `CONTAINS` |
| `multitenancy.enabled` | `multitenancy_enabled` | `true` |
| `spring.config.import` | `UIDAM_CONFIG_IMPORT` | `optional:classpath:tenant-default.properties,...` |

### 1.6 Cleanup Job

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `cleanup.job.batch.size` | `CLEANUP_JOB_BATCH_SIZE` | `50000` |
| `cleanup.job.scheduling.rate.cron` | `CLEANUP_JOB_SCHEDULING_RATE_CRON` | `0 0 */6 * * *` |
| `cleanup.job.scheduling.retry.attempts` | `CLEANUP_JOB_SCHEDULING_RETRY_ATTEMPTS` | `3` |
| `cleanup.token.expires.before` | `CLEANUP_TOKEN_EXPIRES_BEFORE_IN_DAYS` | `1` |

### 1.7 Cache

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `cache.expire.mins` | `cache_expire_mins` | `60` |
| `cache.max.size` | `cache_max_size` | `100` |
| `cache.client.ids` | `cache_client_ids` | `token-mgmt,device-mgmt` |

### 1.8 CORS & Logout

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `cors.allowed.origin.patterns` | `cors_allowed_origin_patterns` | `*.harmandev.com,*.harman.com` |
| `cors.allowed.methods` | `cors_allowed_methods` | `GET,HEAD,POST` |
| `logout.redirect.whitelisted.custom.hosts` | `LOGOUT_REDIRECT_WHITELISTED_CUSTOM_HOSTS` | `localhost,127.0.0.1` |

### 1.9 Health & Actuators

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `management.endpoint.health.show-details` | `management_endpoint_health_show-details` | `always` |
| `management.endpoint.health.probes.enabled` | `management_endpoint_health_probes_enabled` | `true` |
| `management.health.livenessState.enabled` | `management_health_livenessState_enabled` | `true` |
| `management.health.readinessState.enabled` | `management_health_readinessState_enabled` | `true` |
| `management.health.db.enabled` | `management_health_db_enabled` | `false` |
| `management.endpoints.web.exposure.include` | `management_endpoints_web_exposure_include` | `health,info,prometheus,metrics,refresh` |
| `health.postgresdb.monitor.enabled` | `health_postgresdb_monitor_enabled` | `false` |
| `health.postgresdb.monitor.restart.on.failure` | `health_postgresdb_monitor_restart_on_failure` | `false` |

### 1.10 Metrics – Prometheus

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `metrics.prometheus.enabled` | `metrics_prometheus_enabled` | `false` |
| `prometheus.agent.port` | `prometheus_agent_port` | `9100` |
| `prometheus.agent.port.exposed` | `prometheus_agent_port_exposed` | `9100` |
| `management.prometheus.metrics.export.enabled` | `metrics_prometheus_enabled` | `false` |
| `management.endpoints.web.path-mapping.prometheus` | `metrics_prometheus_path` | `/prometheus` |

### 1.11 Metrics – Datadog

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `management.datadog.metrics.export.enabled` | `metrics_datadog_enabled` | `false` |
| `management.datadog.metrics.export.api-key` | `metrics_datadog_apiKey` | `api-key` |
| `management.datadog.metrics.export.application-key` | `metrics_datadog_applicationKey` | `applicationKey` |
| `management.datadog.metrics.export.descriptions` | `metrics_datadog_descriptions` | `true` |
| `management.datadog.metrics.export.uri` | `metrics_datadog_uri` | `https://api.datadoghq.eu` |
| `management.datadog.metrics.export.step` | `metrics_datadog_step` | `30s` |
| `management.datadog.metrics.export.read-timeout` | `metrics_datadog_readTimeout` | `5s` |
| `management.datadog.metrics.export.connect-timeout` | `metrics_datadog_connectTimeout` | `5s` |
| `management.datadog.metrics.export.batch-size` | `metrics_datadog_batchSize` | `1000` |

### 1.12 Logging (Graylog)

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `APP_GRAYLOG_ENABLED` | `GRAYLOG_ENABLED` | `false` |
| `APP_GRAYLOG_HOST` | `GRAYLOG_HOST` | `graylog.default.svc.cluster.local` |
| `APP_GRAYLOG_PORT` | `GRAYLOG_PORT` | `12201` |
| `APP_NEVER_BLOCK_FOR_GRAYLOG` | `NEVER_BLOCK_FOR_GRAYLOG` | `false` |
| `APP_LOG_FOLDER` | `LOG_FOLDER` | `logs/` |
| `APP_LOG_LEVEL` | `LOG_LEVEL` | `ERROR` |
| `APP_SVC_LOG_LEVEL` | `SVC_LOG_LEVEL` | `ERROR` |
| `APP_SPRING_LOG_LEVEL` | `SPRING_LOG_LEVEL` | `ERROR` |
| `APP_PROP_LOAD_LOG_LEVEL` | `PROP_LOAD_LOG_LEVEL` | `INFO` |

### 1.13 Config Server

| Property Name | ENV Variable | Default Value |
|---|---|---|
| `spring.cloud.config.uri` | `CONFIG_SERVER_HOST` | `http://localhost:8888` |
| `spring.cloud.config.enabled` | `CONFIG_SERVER_ENABLED` | `false` |
| `spring.cloud.config.retry.max-attempts` | `CONFIG_SERVER_RETRY_MAX_ATTEMPTS` | `6` |
| `spring.cloud.config.retry.initial-interval` | `CONFIG_SERVER_RETRY_INITIAL_INTERVAL` | `1000` |
| `spring.cloud.config.retry.max-interval` | `CONFIG_SERVER_RETRY_MAX_INTERVAL` | `2000` |

---

## 2. Tenant Default Properties

> File: `tenant-default.properties`  
> Property prefix in file: `tenant.props.default.<property>`

### 2.1 Database

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `jdbc-url` | `tenant.props.default.jdbc-url` | `DEFAULT_POSTGRES_DATASOURCE` | `jdbc:postgresql://localhost:5432/ChangeMe` | `tenants_profile_<TENANTID>_jdbc-url` |
| `user-name` | `tenant.props.default.user-name` | `DEFAULT_POSTGRES_USERNAME` | `ChangeMe` | `tenants_profile_<TENANTID>_user-name` |
| `password` | `tenant.props.default.password` | `DEFAULT_POSTGRES_PASSWORD` | `ChangeMe` | `tenants_profile_<TENANTID>_password` |
| `max-pool-size` | `tenant.props.default.max-pool-size` | `DEFAULT_POSTGRES_MAX_POOL_SIZE` | `30` | `tenants_profile_<TENANTID>_max-pool-size` |
| `max-idle-time` | `tenant.props.default.max-idle-time` | `DEFAULT_POSTGRES_MAX_IDLE_TIME` | `0` | `tenants_profile_<TENANTID>_max-idle-time` |
| `connection-timeout-ms` | `tenant.props.default.connection-timeout-ms` | `DEFAULT_POSTGRES_CONNECTION_TIMEOUT_MS` | `60000` | `tenants_profile_<TENANTID>_connection-timeout-ms` |
| `default-schema` | `tenant.props.default.default-schema` | `DEFAULT_POSTGRES_DEFAULT_SCHEMA` | `uidam` | `tenants_profile_<TENANTID>_default-schema` |
| `cache-prep-stmts` | `tenant.props.default.cache-prep-stmts` | `DEFAULT_POSTGRES_CACHE_PREP_STMTS` | `true` | `tenants_profile_<TENANTID>_cache-prep-stmts` |
| `prep-stmt-cache-size` | `tenant.props.default.prep-stmt-cache-size` | `DEFAULT_POSTGRES_PREP_STMT_CACHE_SIZE` | `250` | `tenants_profile_<TENANTID>_prep-stmt-cache-size` |
| `prep-stmt-cache-sql-limit` | `tenant.props.default.prep-stmt-cache-sql-limit` | `DEFAULT_POSTGRES_PREP_STMT_CACHE_SQL_LIMIT` | `2048` | `tenants_profile_<TENANTID>_prep-stmt-cache-sql-limit` |

### 2.2 Basic Tenant Identity

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `tenant-id` | `tenant.props.default.tenant-id` | `TENANT_DEFAULT` | `default` | `tenants_profile_<TENANTID>_tenant-id` |
| `tenant-name` | `tenant.props.default.tenant-name` | `DEFAULT_TENANT_NAME` | `default` | `tenants_profile_<TENANTID>_tenant-name` |
| `jks-enabled` | `tenant.props.default.jks-enabled` | `DEFAULT_JKS_ENABLED` | `true` | `tenants_profile_<TENANTID>_jks-enabled` |
| `alias` | `tenant.props.default.alias` | `DEFAULT_TENANT_ALIAS` | `default` | `tenants_profile_<TENANTID>_alias` |

### 2.3 Account Configuration

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `account.account-id` | `tenant.props.default.account.account-id` | `DEFAULT_TENANT_ACCOUNT_ID` | `10001` | `tenants_profile_<TENANTID>_account_account-id` |
| `account.account-name` | `tenant.props.default.account.account-name` | `DEFAULT_TENANT_ACCOUNT_NAME` | `default` | `tenants_profile_<TENANTID>_account_account-name` |
| `account.account-type` | `tenant.props.default.account.account-type` | `DEFAULT_TENANT_ACCOUNT_TYPE` | `Root` | `tenants_profile_<TENANTID>_account_account-type` |
| `account.account-field-enabled` | `tenant.props.default.account.account-field-enabled` | `DEFAULT_ACCOUNT_FIELD_ENABLED` | `true` | `tenants_profile_<TENANTID>_account_account-field-enabled` |

### 2.4 OAuth Client Configuration

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `client.access-token-ttl` | `tenant.props.default.client.access-token-ttl` | `DEFAULT_TENANT_CLIENT_ACCESS_TOKEN_TTL` | `3600` | `tenants_profile_<TENANTID>_client_access-token-ttl` |
| `client.id-token-ttl` | `tenant.props.default.client.id-token-ttl` | `DEFAULT_TENANT_CLIENT_ID_TOKEN_TTL` | `3600` | `tenants_profile_<TENANTID>_client_id-token-ttl` |
| `client.refresh-token-ttl` | `tenant.props.default.client.refresh-token-ttl` | `DEFAULT_TENANT_CLIENT_REFRESH_TOKEN_TTL` | `3600` | `tenants_profile_<TENANTID>_client_refresh-token-ttl` |
| `client.auth-code-ttl` | `tenant.props.default.client.auth-code-ttl` | `DEFAULT_TENANT_CLIENT_AUTH_CODE_TTL` | `300` | `tenants_profile_<TENANTID>_client_auth-code-ttl` |
| `client.oauth-scope-customization` | `tenant.props.default.client.oauth-scope-customization` | `DEFAULT_TENANT_OAUTH_SCOPE_CUSTOMIZATION` | `false` | `tenants_profile_<TENANTID>_client_oauth-scope-customization` |
| `client.reuse-refresh-token` | `tenant.props.default.client.reuse-refresh-token` | `DEFAULT_TENANT_CLIENT_REUSE_REFRESH_TOKEN` | `false` | `tenants_profile_<TENANTID>_client_reuse-refresh-token` |
| `client.secret-encryption-key` | `tenant.props.default.client.secret-encryption-key` | `DEFAULT_TENANT_CLIENT_SECRET_ENCRYPTION_KEY` | `ChangeMe` | `tenants_profile_<TENANTID>_client_secret-encryption-key` |
| `client.secret-encryption-salt` | `tenant.props.default.client.secret-encryption-salt` | `DEFAULT_TENANT_CLIENT_SECRET_ENCRYPTION_SALT` | `ChangeMe` | `tenants_profile_<TENANTID>_client_secret-encryption-salt` |

### 2.5 Contact Details

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `password-recovery-url` | `tenant.props.default.password-recovery-url` | `DEFAULT_TENANT_PASSWORD_RECOVERY_URL` | `http://localhost:9443/recovery` | `tenants_profile_<TENANTID>_password-recovery-url` |
| `contact-details.contact-name` | `tenant.props.default.contact-details.contact-name` | `DEFAULT_TENANT_CONTACT_NAME` | *(empty)* | `tenants_profile_<TENANTID>_contact-details_contact-name` |
| `contact-details.phone-number` | `tenant.props.default.contact-details.phone-number` | `DEFAULT_TENANT_PHONE_NUMBER` | *(empty)* | `tenants_profile_<TENANTID>_contact-details_phone-number` |
| `contact-details.email` | `tenant.props.default.contact-details.email` | `DEFAULT_TENANT_EMAIL` | *(empty)* | `tenants_profile_<TENANTID>_contact-details_email` |

### 2.6 User Configuration

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `user.captcha-after-invalid-failures` | `tenant.props.default.user.captcha-after-invalid-failures` | `DEFAULT_TENANT_USER_CAPTCHA_AFTER_INVALID_FAILURES` | `1` | `tenants_profile_<TENANTID>_user_captcha-after-invalid-failures` |
| `user.captcha-required` | `tenant.props.default.user.captcha-required` | `DEFAULT_TENANT_USER_CAPTCHA_REQUIRED` | `false` | `tenants_profile_<TENANTID>_user_captcha-required` |
| `user.max-allowed-login-attempts` | `tenant.props.default.user.max-allowed-login-attempts` | `DEFAULT_TENANT_USER_MAX_ALLOWED_LOGIN_ATTEMPTS` | `3` | `tenants_profile_<TENANTID>_user_max-allowed-login-attempts` |
| `user.default-role` | `tenant.props.default.user.default-role` | `DEFAULT_TENANT_USER_DEFAULT_ROLE` | `VEHICLE_OWNER` | `tenants_profile_<TENANTID>_user_default-role` |
| `user.jwt-additional-claim-attributes` | `tenant.props.default.user.jwt-additional-claim-attributes` | `DEFAULT_JWT_ADDITIONAL_CLAIM_ATTRIBUTES` | *(empty)* | `tenants_profile_<TENANTID>_user_jwt-additional-claim-attributes` |
| `external-idp-details.client-id` | `tenant.props.default.external-idp-details.client-id` | `DEFAULT_TENANT_EXTERNAL_IDP_CLIENT_ID` | *(empty)* | `tenants_profile_<TENANTID>_external-idp-details_client-id` |
| `external-idp-details.secret` | `tenant.props.default.external-idp-details.secret` | `DEFAULT_TENANT_EXTERNAL_IDP_SECRET` | *(empty)* | `tenants_profile_<TENANTID>_external-idp-details_secret` |

### 2.7 External URLs

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `external-urls.user-management-base-url` | `tenant.props.default.external-urls.user-management-base-url` | `DEFAULT_USER_MANAGEMENT_ENV` | `http://localhost:8080` | `tenants_profile_<TENANTID>_external-urls_user-management-base-url` |
| `external-urls.user-by-username-endpoint` | `tenant.props.default.external-urls.user-by-username-endpoint` | `DEFAULT_USER_BY_USERNAME_ENDPOINT` | `/v1/users/{userName}/byUserName` | `tenants_profile_<TENANTID>_external-urls_user-by-username-endpoint` |
| `external-urls.client-by-client-id-endpoint` | `tenant.props.default.external-urls.client-by-client-id-endpoint` | `DEFAULT_CLIENT_BY_CLIENT_ID_ENDPOINT` | `/v1/oauth2/client/{clientId}` | `tenants_profile_<TENANTID>_external-urls_client-by-client-id-endpoint` |
| `external-urls.add-user-events-endpoint` | `tenant.props.default.external-urls.add-user-events-endpoint` | `DEFAULT_ADD_USER_EVENTS_ENDPOINT` | `/v1/users/{id}/events` | `tenants_profile_<TENANTID>_external-urls_add-user-events-endpoint` |
| `external-urls.user-recovery-notif-endpoint` | `tenant.props.default.external-urls.user-recovery-notif-endpoint` | `DEFAULT_USER_RECOVERY_NOTIFICATION_ENDPOINT` | `/v1/users/{userName}/recovery/forgotpassword` | `tenants_profile_<TENANTID>_external-urls_user-recovery-notif-endpoint` |
| `external-urls.reset-password-endpoint` | `tenant.props.default.external-urls.reset-password-endpoint` | `DEFAULT_USER_UPDATE_PASSWORD_USING_RECOVERY_SECRET_ENDPOINT` | `/v1/users/recovery/set-password` | `tenants_profile_<TENANTID>_external-urls_reset-password-endpoint` |
| `external-urls.self-create-user-endpoint` | `tenant.props.default.external-urls.self-create-user-endpoint` | `DEFAULT_CREATE_USER_ENDPOINT` | `/v1/users/self` | `tenants_profile_<TENANTID>_external-urls_self-create-user-endpoint` |
| `external-urls.password-policy-endpoint` | `tenant.props.default.external-urls.password-policy-endpoint` | `DEFAULT_PASSWORD_POLICY_ENDPOINT` | `/v1/users/password-policy` | `tenants_profile_<TENANTID>_external-urls_password-policy-endpoint` |
| `external-urls.create-fedrated-user-endpoint` | `tenant.props.default.external-urls.create-fedrated-user-endpoint` | `DEFAULT_CREATE_FEDRATED_USER_ENDPOINT` | `/v1/users/federated` | `tenants_profile_<TENANTID>_external-urls_create-fedrated-user-endpoint` |

### 2.8 Feature Flags

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `sign-up-enabled` | `tenant.props.default.sign-up-enabled` | `DEFAULT_TENANT_SIGN_UP_ENABLED` | `true` | `tenants_profile_<TENANTID>_sign-up-enabled` |
| `external-idp-enabled` | `tenant.props.default.external-idp-enabled` | `DEFAULT_TENANT_EXTERNAL_IDP_ENABLED` | `false` | `tenants_profile_<TENANTID>_external-idp-enabled` |
| `internal-login-enabled` | `tenant.props.default.internal-login-enabled` | `DEFAULT_TENANT_INTERNAL_LOGIN_ENABLED` | `true` | `tenants_profile_<TENANTID>_internal-login-enabled` |
| `external-idp-client-name` | `tenant.props.default.external-idp-client-name` | `DEFAULT_TENANT_EXTERNAL_IDP_CLIENT_NAME` | `federated-user-client` | `tenants_profile_<TENANTID>_external-idp-client-name` |

### 2.9 UI Configuration

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `ui.logo-path` | `tenant.props.default.ui.logo-path` | `DEFAULT_TENANT_UI_LOGO_PATH` | `/images/default-logo.svg` | `tenants_profile_<TENANTID>_ui_logo-path` |
| `ui.stylesheet-path` | `tenant.props.default.ui.stylesheet-path` | `DEFAULT_TENANT_UI_STYLESHEET_PATH` | `/css/style.css` | `tenants_profile_<TENANTID>_ui_stylesheet-path` |
| `ui.terms-privacy-policy` | `tenant.props.default.ui.terms-privacy-policy` | `DEFAULT_TENANT_UI_TERMS_PRIVACY_POLICY` | `https://www.xyz.com/terms-and-privacy-policy` | `tenants_profile_<TENANTID>_ui_terms-privacy-policy` |

### 2.10 Key Store / JWT

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `key-store.key-store-filename` | `tenant.props.default.key-store.key-store-filename` | `DEFAULT_KEYSTORE_FILE_NAME` | `uidamauthserver.jks` | `tenants_profile_<TENANTID>_key-store_key-store-filename` |
| `key-store.key-store-jks-encoded-content` | `tenant.props.default.key-store.key-store-jks-encoded-content` | `DEFAULT_KEYSTORE_JKS_ENCODED_CONTENT` | *(empty)* | `tenants_profile_<TENANTID>_key-store_key-store-jks-encoded-content` |
| `key-store.key-store-password` | `tenant.props.default.key-store.key-store-password` | `DEFAULT_KEYSTORE_PASS` | `uidam-test-pwd` | `tenants_profile_<TENANTID>_key-store_key-store-password` |
| `key-store.key-alias` | `tenant.props.default.key-store.key-alias` | `DEFAULT_KEYSTORE_ALIAS` | `uidam-dev` | `tenants_profile_<TENANTID>_key-store_key-alias` |
| `key-store.key-type` | `tenant.props.default.key-store.key-type` | `DEFAULT_KEYSTORE_TYPE` | `JKS` | `tenants_profile_<TENANTID>_key-store_key-type` |
| `key-store.jwt-public-key-path` | `tenant.props.default.key-store.jwt-public-key-path` | `DEFAULT_JWT_PUBLIC_KEY_PEM_PATH` | `uidampubkey.pem` | `tenants_profile_<TENANTID>_key-store_jwt-public-key-path` |
| `key-store.jwt-key-id` | `tenant.props.default.key-store.jwt-key-id` | `DEFAULT_JWT_KEY_ID` | `8d845b3g-246m-8b5f-af5b-gh8c9922f14g` | `tenants_profile_<TENANTID>_key-store_jwt-key-id` |
| `cert.jwt-public-key` | `tenant.props.default.cert.jwt-public-key` | `DEFAULT_JWT_PUBLIC_KEY` | `app.pub` | `tenants_profile_<TENANTID>_cert_jwt-public-key` |
| `cert.jwt-private-key` | `tenant.props.default.cert.jwt-private-key` | `DEFAULT_JWT_PRIVATE_KEY` | `app.key` | `tenants_profile_<TENANTID>_cert_jwt-private-key` |
| `cert.jwt-key-id` | `tenant.props.default.cert.jwt-key-id` | `DEFAULT_JWT_KEY_ID` | `8d845b3g-246m-8b5f-af5b-gh8c9922f14g` | `tenants_profile_<TENANTID>_cert_jwt-key-id` |

### 2.11 Captcha

| Property Name | Default Property | ENV Variable | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `captcha.recaptcha-key-site` | `tenant.props.default.captcha.recaptcha-key-site` | `DEFAULT_TENANT_CAPTCHA_RECAPTCHA_KEY_SITE` | `TO-BE-UPDATED` | `tenants_profile_<TENANTID>_captcha_recaptcha-key-site` |
| `captcha.recaptcha-key-secret` | `tenant.props.default.captcha.recaptcha-key-secret` | `DEFAULT_TENANT_CAPTCHA_RECAPTCHA_KEY_SECRET` | `TO-BE-UPDATED` | `tenants_profile_<TENANTID>_captcha_recaptcha-key-secret` |
| `captcha.recaptcha-verify-url` | `tenant.props.default.captcha.recaptcha-verify-url` | `DEFAULT_TENANT_CAPTCHA_RECAPTCHA_VERIFY_URL` | `https://www.google.com/recaptcha/api/siteverify` | `tenants_profile_<TENANTID>_captcha_recaptcha-verify-url` |

### 2.12 External IDP – Registered Client List


> **Per-tenant override:** All ENV variable names in this section follow the
> `tenants_profile_<TENANTID>_<PROPERTY>` convention — replace `<TENANTID>` with the
> actual tenant ID (e.g. for tenant `ecsp`, use `tenants_profile_ecsp_<PROPERTY>`).

> Index `[N]` refers to the list position: `[0]` = Google, `[1]` = GitHub, `[2]` = Cognito, `[3]` = Azure.

| Property Name | Default Property | ENV Variable (index N) | Default Value | Tenant Property (`tenants_profile_<TENANTID>_<property>`) |
|---|---|---|---|---|
| `external-idp-registered-client-list[N].client-name` | `tenant.props.default.external-idp-registered-client-list[N].client-name` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CLIENT_NAME` | `Google` / `GitHub` / `Cognito` / `Azure` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_client-name` |
| `external-idp-registered-client-list[N].registration-id` | `tenant.props.default.external-idp-registered-client-list[N].registration-id` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_REGISTRATION_ID` | `google` / `github` / `cognito` / `azureidp` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_registration-id` |
| `external-idp-registered-client-list[N].client-id` | `tenant.props.default.external-idp-registered-client-list[N].client-id` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CLIENT_ID` | `TO-BE-UPDATED` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_client-id` |
| `external-idp-registered-client-list[N].client-secret` | `tenant.props.default.external-idp-registered-client-list[N].client-secret` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CLIENT_SECRET` | `TO-BE-UPDATED` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_client-secret` |
| `external-idp-registered-client-list[N].client-authentication-method` | `tenant.props.default.external-idp-registered-client-list[N].client-authentication-method` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CLIENT_AUTHENTICATION_METHOD` | `client_secret_basic` / `client_secret_post` (Azure) | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_client-authentication-method` |
| `external-idp-registered-client-list[N].scope` | `tenant.props.default.external-idp-registered-client-list[N].scope` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_SCOPE` | `openid, profile, email, address, phone` / `read:user` / `openid,profile` / `openid` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_scope` |
| `external-idp-registered-client-list[N].authorization-uri` | `tenant.props.default.external-idp-registered-client-list[N].authorization-uri` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_AUTHORIZATION_URI` | *(IDP-specific)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_authorization-uri` |
| `external-idp-registered-client-list[N].token-uri` | `tenant.props.default.external-idp-registered-client-list[N].token-uri` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_TOKEN_URI` | *(IDP-specific)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_token-uri` |
| `external-idp-registered-client-list[N].user-info-uri` | `tenant.props.default.external-idp-registered-client-list[N].user-info-uri` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_USER_INFO_URI` | *(IDP-specific)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_user-info-uri` |
| `external-idp-registered-client-list[N].user-name-attribute-name` | `tenant.props.default.external-idp-registered-client-list[N].user-name-attribute-name` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_USER_NAME_ATTRIBUTE_NAME` | `sub` / `id` (GitHub) | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_user-name-attribute-name` |
| `external-idp-registered-client-list[N].jwk-set-uri` | `tenant.props.default.external-idp-registered-client-list[N].jwk-set-uri` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_JWK_SET_URI` | *(IDP-specific)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_jwk-set-uri` |
| `external-idp-registered-client-list[N].token-info-source` | `tenant.props.default.external-idp-registered-client-list[N].token-info-source` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_TOKEN_INFO_SOURCE` | `FETCH_INTERNAL_USER` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_token-info-source` |
| `external-idp-registered-client-list[N].create-user-mode` | `tenant.props.default.external-idp-registered-client-list[N].create-user-mode` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CREATE_USER_MODE` | `CREATE_INTERNAL_USER` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_create-user-mode` |
| `external-idp-registered-client-list[N].default-user-roles` | `tenant.props.default.external-idp-registered-client-list[N].default-user-roles` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_DEFAULT_USER_ROLES` | `VEHICLE_OWNER` | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_default-user-roles` |
| `external-idp-registered-client-list[N].claimMappings` | `tenant.props.default.external-idp-registered-client-list[N].claimMappings` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CLAIM_MAPPINGS` | *(IDP-specific)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_claimMappings` |
| `external-idp-registered-client-list[N].conditions.claimKey` | `tenant.props.default.external-idp-registered-client-list[N].conditions.claimKey` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CONDITIONS_CLAIM_KEY` | *(empty)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_conditions_claimKey` |
| `external-idp-registered-client-list[N].conditions.expectedValue` | `tenant.props.default.external-idp-registered-client-list[N].conditions.expectedValue` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CONDITIONS_EXPECTED_VALUE` | *(empty)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_conditions_expectedValue` |
| `external-idp-registered-client-list[N].conditions.operator` | `tenant.props.default.external-idp-registered-client-list[N].conditions.operator` | `DEFAULT_EXTERNAL_IDP_REGISTERED_CLIENT_LIST_N_CONDITIONS_OPERATOR` | *(empty)* | `tenants_profile_<TENANTID>_external-idp-registered-client-list[N]_conditions_operator` |


---

*End of document*
