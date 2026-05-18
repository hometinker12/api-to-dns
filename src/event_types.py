"""Canonical activity log event_type identifiers."""

# HTTP
EVENT_HTTP_REQUEST = "http.request"

# Authentication
EVENT_AUTH_LOGIN_FAILED = "auth.login_failed"
EVENT_AUTH_LOGIN_SUCCEEDED = "auth.login_succeeded"
EVENT_AUTH_LOGOUT = "auth.logout"

# DNS zones (admin UI)
EVENT_DNS_ZONE_CREATED = "dns_zone.created"
EVENT_DNS_ZONE_UPDATED = "dns_zone.updated"
EVENT_DNS_ZONE_DELETED = "dns_zone.deleted"

# API keys
EVENT_API_KEY_CREATED = "api_key.created"
EVENT_API_KEY_UPDATED = "api_key.updated"
EVENT_API_KEY_REVOKED = "api_key.revoked"

# DNS API
EVENT_DNS_ACCESS_DENIED = "dns.access_denied"
EVENT_DNS_INVALID_REQUEST = "dns.invalid_request"
EVENT_DNS_PROVIDER_FAILED = "dns.provider_failed"

# Users
EVENT_USER_PASSWORD_CHANGED = "user.password_changed"
EVENT_USER_CREATED = "user.created"
EVENT_USER_DISABLED = "user.disabled"
EVENT_USER_ENABLED = "user.enabled"
EVENT_USER_DELETED = "user.deleted"
EVENT_USER_PASSWORD_RESET = "user.password_reset"
EVENT_USER_ROLES_UPDATED = "user.roles_updated"

# Plugins and system
EVENT_PLUGIN_DISABLED = "plugin.disabled"
EVENT_PLUGIN_ENABLED = "plugin.enabled"
EVENT_SYSTEM_LOG_LEVEL_CHANGED = "system.log_level_changed"
EVENT_SYSTEM_RETENTION_CHANGED = "system.retention_changed"
EVENT_SYSTEM_SMTP_UPDATED = "system.smtp_updated"
EVENT_SYSTEM_LOG_ROTATION_UPDATED = "system.log_rotation_updated"

# Alert rules
EVENT_ALERT_RULE_CREATED = "alert_rule.created"
EVENT_ALERT_RULE_UPDATED = "alert_rule.updated"
EVENT_ALERT_RULE_DELETED = "alert_rule.deleted"
EVENT_ALERT_EMAIL_SENT = "alert.email_sent"
EVENT_ALERT_EMAIL_FAILED = "alert.email_failed"
