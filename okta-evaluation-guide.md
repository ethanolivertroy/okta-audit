# Okta FedRAMP and NIST 800-53 Compliance Evaluation Guide

This guide provides a systematic approach to manually evaluate an Okta implementation for FedRAMP and NIST 800-53 compliance, complementing the automated `okta-audit.sh` script. It follows the same assessment areas as the script but provides step-by-step instructions for a hands-on evaluation.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Authentication Types & Phishing-Resistant MFA](#1-authentication-types--phishing-resistant-mfa)
3. [Management Console Login Security](#2-management-console-login-security)
4. [FIPS Compliance](#3-fips-compliance)
5. [Integration Validation](#4-integration-validation)
6. [Admin Role Review](#6-admin-role-review)
7. [Admin Group Assignments](#7-admin-group-assignments)
8. [User Status Review](#8-user-status-review)
9. [Password Policy Review](#9-password-policy-review)
10. [SIEM Integration & Monitoring](#11-siem-integration--monitoring)
11. [Behavioral Detection & Threat Insight](#12-behavioral-detection--threat-insight)
12. [Notification Settings](#13-notification-settings)
13. [API Token Management](#14-api-token-management)
14. [Federal Subscription Validation](#15-federal-subscription-validation)
15. [NIST 800-53 Control Matrix](#nist-800-53-control-matrix)
16. [Security Best Practices](#16-security-best-practices)
17. [DISA STIG Requirements](#17-disa-stig-requirements)

## Prerequisites

Before beginning your evaluation, ensure you have:

1. **Administrative access** to the Okta tenant being evaluated
2. **API token** with appropriate permissions:
   ```
   export OKTA_API_TOKEN="your-api-token"
   export OKTA_DOMAIN="your-org.okta.com"  # Or .okta.gov for Fed instances
   ```
3. **Required tools**:
   - Command line with `curl` and `jq` installed
   - Web browser for Admin Console access
4. **Documentation** of your organization's security requirements

## 1. Authentication Types & Phishing-Resistant MFA

### Admin Console Steps
1. Navigate to **Security → Authenticators**
2. Document all enabled authenticator methods
3. Verify phishing-resistant options (FIDO2/WebAuthn) are enabled
4. Go to **Security → Authentication Policies**
5. Review default policy and any custom authentication policies
6. Check global session settings under **Security → Authentication**

### API Verification
Execute these commands and save the outputs for your documentation:

```bash
# Get MFA enrollment policies
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" | jq > mfa_enrollment_policies.json

# Get FIDO2 authenticator configuration
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/authenticators" | jq > authenticators.json
```

### FedRAMP Requirements Checklist
- [ ] FIDO2/WebAuthn authenticators are enabled
- [ ] Non-compliant authentication methods are disabled or restricted
- [ ] MFA enrollment policy enforces phishing-resistant authentication
- [ ] Authenticator attestation is configured appropriately
- [ ] FIDO2 policy aligns with NIST 800-63B AAL3 where required

## 2. Management Console Login Security

### Admin Console Steps
1. Navigate to **Security → Authentication Policies**
2. Review the Administrator policy specifically
3. Verify MFA is required for all admin access
4. Go to **Security → General**
5. Check session lifetime settings
6. Review login attempts before lockout

### API Verification
```bash
# Check sign-on policies
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" | jq > sign_on_policies.json

# Check session settings
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/sessions/me" | jq > session_info.json
```

### FedRAMP Requirements Checklist
- [ ] Administrator access requires phishing-resistant MFA
- [ ] Session timeout is set to 15-30 minutes (inactivity)
- [ ] Maximum session length complies with organizational policy 
- [ ] Account lockout is set after 3-5 unsuccessful attempts
- [ ] Admin access is restricted to authorized networks where applicable

## 3. FIPS Compliance

### Admin Console Steps
1. Check domain - should be `.okta.gov` or `.okta.mil` for FedRAMP High
2. Navigate to **Security → Authentication** 
3. Review cryptographic settings
4. Check if RSA/Symantec tokens (FIPS certified) are enabled

### API and Manual Verification
```bash
# Check TLS and cryptographic settings
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/authorizationServers/default" | jq > default_auth_server.json

# Check FIPS mode through Factors API
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/org/factors" | jq > org_factors.json

# Check IdP settings for FIPS-compliant SHA-256 algorithms
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/idps" | jq > idp_settings.json
```

Additional manual check:
1. Try accessing `https://support.okta-gov.com/help/s/status`
2. Contact your Okta representative to confirm FedRAMP environment

### FIPS Compliance Checklist
- [ ] Domain is `.okta.gov` or `.okta.mil` for FedRAMP High
- [ ] TLS 1.2+ with FIPS-approved cipher suites in use
- [ ] FIPS 140-2/140-3 validated cryptographic modules confirmed
- [ ] Hardware security keys are FIPS 140-2/140-3 certified
- [ ] SHA-256 or stronger signature algorithms in use

## 4. Integration Validation

### Admin Console Steps
1. Navigate to **Applications → Applications**
2. Document all active applications
3. Verify application settings align with security requirements
4. Check application assignment to appropriate groups

### API Verification
```bash
# List all applications
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/apps?limit=200" | jq > apps.json

# For each app of interest, check its assignments
APP_ID="your-app-id"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/apps/${APP_ID}/users" | jq > app_users.json
```

### Application Security Checklist
- [ ] All applications are documented and approved
- [ ] SAML applications use SHA-256 or stronger signatures
- [ ] OAuth/OIDC apps have appropriate scope limitations
- [ ] Proper group assignments are in place
- [ ] No unauthorized applications are present

## 6. Admin Role Review

### Admin Console Steps
1. Navigate to **Directory → People**
2. Filter for administrators 
3. Check each admin user for:
   - Role assignments
   - Group memberships
   - Last login time
   - Account status

### API Verification
```bash
# List all users
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?limit=200" | jq > users.json

# For specific admin users, check roles
USER_ID="admin-user-id"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users/${USER_ID}/roles" | jq > user_roles.json
```

### Admin Role Checklist
- [ ] Admin roles follow the principle of least privilege
- [ ] No excessive Super Admin assignments
- [ ] Admin accounts have appropriate MFA enforced
- [ ] Privileged roles are properly documented
- [ ] Service accounts have appropriate permissions

## 7. Admin Group Assignments

### Admin Console Steps
1. Navigate to **Directory → Groups**
2. Identify administrator groups
3. Review group rules and assignments
4. Check nested group memberships
5. Verify dynamic group rules where applicable

### API Verification
```bash
# List all groups
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/groups?limit=200" | jq > groups.json

# For admin groups, check members
GROUP_ID="admin-group-id"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/groups/${GROUP_ID}/users" | jq > group_members.json
```

### Admin Group Checklist
- [ ] Clear naming conventions for admin groups
- [ ] No excessive membership in privileged groups
- [ ] Group rules correctly maintain membership
- [ ] Group assignment processes are documented
- [ ] Appropriate admin groups for each application

## 8. User Status Review

### Admin Console Steps
1. Navigate to **Directory → People**
2. Filter by status (Active, Locked Out, Suspended, etc.)
3. Verify proper handling of inactive accounts
4. Check for accounts needing password reset
5. Review deprovisioning procedures

### API Verification
```bash
# Check users by status
for STATUS in ACTIVE LOCKED_OUT PASSWORD_EXPIRED RECOVERY SUSPENDED DEPROVISIONED; do
  curl -s -X GET \
    -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
    -H "Accept: application/json" \
    "https://${OKTA_DOMAIN}/api/v1/users?limit=200&filter=status%20eq%20%22${STATUS}%22" \
    | jq > "users_${STATUS}.json"
done

# Find inactive users (multiple methods)

# Method 1: Using search parameter with last login date (preferred method)
NINETY_DAYS_AGO=$(date -u -d '90 days ago' +"%Y-%m-%dT%H:%M:%S.000Z")
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?search=last_login%20lt%20%22${NINETY_DAYS_AGO}%22&limit=200" \
  | jq > inactive_users_by_login.json

# Method 2: Combine users with inactive statuses
mkdir -p inactive_users_by_status
for STATUS in SUSPENDED DEPROVISIONED LOCKED_OUT PASSWORD_EXPIRED; do
  # Use status files we already retrieved if available
  if [ -f "users_${STATUS}.json" ]; then
    cp "users_${STATUS}.json" "inactive_users_by_status/inactive_${STATUS}.json"
  else
    curl -s -X GET \
      -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
      -H "Accept: application/json" \
      "https://${OKTA_DOMAIN}/api/v1/users?filter=status%20eq%20%22${STATUS}%22&limit=200" \
      | jq > "inactive_users_by_status/inactive_${STATUS}.json"
  fi
done

# Method 3: Local filtering with jq (if API methods fail)
if [ -f "users_ACTIVE.json" ]; then
  jq --arg date "${NINETY_DAYS_AGO}" '[.[] | select(.lastLogin != null and .lastLogin < $date)]' \
    users_ACTIVE.json > inactive_by_jq_filter.json
fi

# Combine all inactive user results into one file
jq -s 'add | unique_by(.id)' inactive_users_by_login.json inactive_users_by_status/*.json inactive_by_jq_filter.json > inactive_users_combined.json
```

### User Account Management Checklist
- [ ] Clear process for handling inactive accounts
- [ ] Automated deactivation after 90 days of inactivity
- [ ] Locked out accounts are properly investigated
- [ ] No excessive suspended accounts without resolution
- [ ] Provisioning/deprovisioning procedures are documented

## 9. Password Policy Review

### Admin Console Steps
1. Navigate to **Security → Authentication → Password**
2. Review all password policies
3. Check policy assignments to groups
4. Verify password complexity requirements
5. Check account lockout settings
6. Review password history requirements

### API Verification
```bash
# Get password policies
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" | jq > password_policies.json

# For each policy, get its rules
POLICY_ID="policy-id"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${POLICY_ID}/rules" | jq > password_policy_rules.json
```

### Password Policy Checklist
- [ ] Password complexity aligns with NIST SP 800-63B
- [ ] Minimum length ≥ 12 characters
- [ ] Breached password detection enabled
- [ ] Appropriate account lockout thresholds
- [ ] Password policy enforcement is consistent across groups

## 11. SIEM Integration & Monitoring

### Admin Console Steps
1. Navigate to **Reports → System Log**
2. Sample various event types
3. Navigate to **Security → General**
4. Review event hooks or API integrations
5. Verify security monitoring configurations

### API Verification
```bash
# Get recent system logs (last 24 hours)
SINCE=$(date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%SZ")
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000" | jq > system_log_recent.json

# Get failed login attempts
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000&filter=eventType+eq+\"user.authentication.auth_via_mfa\"" \
  | jq > failed_authentication_attempts.json

# Get administrator actions
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000&filter=eventType+sw+\"system.\"" \
  | jq > admin_actions.json
```

### Monitoring Checklist
- [ ] System logs are exported to a SIEM or log management system
- [ ] Administrator actions are monitored and reviewed
- [ ] Failed authentication attempts are tracked and investigated
- [ ] Critical security events trigger alerts
- [ ] Log retention meets FedRAMP requirements (1 year online, 3 years archived)

## 12. Behavioral Detection & Threat Insight

### Admin Console Steps
1. Navigate to **Security → Security Services → Behavior Detection**
2. Check enabled detection rules
3. Navigate to **Security → Security Services → Threat Insight**
4. Verify configuration and excluded zones
5. Check alert settings and response actions

### API Verification
```bash
# Get Threat Insight settings
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/threats/configuration" | jq > threat_insight_settings.json

# Get network zones for cross-reference
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/zones" | jq > network_zones.json
```

### Threat Detection Checklist
- [ ] Behavioral Detection is enabled
- [ ] Threat Insight is properly configured
- [ ] Network zone exclusions are documented and justified
- [ ] Suspicious activity alerts are configured
- [ ] Response actions are appropriate to risk level

## 13. Notification Settings

### Admin Console Steps
1. Navigate to **Settings → General → Security Notifications**
2. Verify admin notification email settings
3. Navigate to **Customizations → Email Templates**
4. Review email customizations for security information

### API Verification
```bash
# Get email templates
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/templates/email" | jq > email_templates.json
```

### Notifications Checklist
- [ ] Security notifications are sent to appropriate personnel
- [ ] Critical alerts have appropriate distribution
- [ ] Email templates comply with organizational standards
- [ ] Users receive appropriate security notifications
- [ ] Customized messages include required security information

## 14. API Token Management

### Admin Console Steps
1. Navigate to **Security → API**
2. Review all active API tokens
3. Check token creation dates and expiry
4. Verify token permissions follow least privilege
5. Document token purpose and ownership

### API Token Checklist
- [ ] Minimum number of API tokens in use
- [ ] Each token has a documented purpose and owner
- [ ] Tokens have appropriate permission scopes
- [ ] Regular rotation schedule is established
- [ ] Inactive tokens are removed

## 15. Federal Subscription Validation

### Manual Verification
1. Confirm domain is `.okta.gov` or `.okta.mil` for FedRAMP High
2. Verify with Okta that tenant is in FedRAMP High environment
3. Review any FedRAMP documentation specific to your Okta instance
4. Check procurement documents reference FedRAMP compliance
5. Verify with your security team that the appropriate FedRAMP package is in place

### FedRAMP Compliance Checklist
- [ ] Domain is `.okta.gov` or `.okta.mil` for FedRAMP High
- [ ] Written confirmation from Okta regarding FedRAMP environment
- [ ] FedRAMP package documentation is available
- [ ] Contractual requirements for FedRAMP are met
- [ ] All FedRAMP-specific controls are implemented

## NIST 800-53 Control Matrix

The following matrix maps key Okta settings to NIST 800-53 controls:

| Control | Description | Evaluation Areas | Okta Settings to Review |
|---------|-------------|------------------|-------------------------|
| **AC-2** | Account Management | User statuses, lifecycle policies | User provisioning/deprovisioning, account status tracking, inactive accounts |
| **AC-3** | Access Enforcement | Sign-on policies, app assignments | Policy enforcement, group assignments, application access rules |
| **AC-7** | Unsuccessful Login Attempts | Password policies, lockout settings | Lockout thresholds, duration, and reset mechanisms |
| **AC-11** | Session Lock | Session settings | Session timeout, maximum session length |
| **IA-2** | Identification and Authentication | MFA enforcement, authenticators | MFA methods, policy enforcement, phishing-resistant options |
| **IA-5** | Authenticator Management | Password policies | Password complexity, history, lifetime, and recovery processes |
| **IA-8** | Non-organizational Users | External IdP settings | Social/external identity providers, consistency of requirements |
| **AU-2** | Audit Events | System logs, monitoring | Event types logged, retention periods, access to logs |
| **SI-4** | Information System Monitoring | Threat detection, behavioral analysis | Threat Insight, behavior detection rules, alerting mechanisms |

## 16. Security Best Practices

This section outlines general security best practices for an Okta tenant beyond compliance requirements.

### Admin Console Steps
1. Review the principle of least privilege:
   - Confirm minimal admin roles and group memberships.
   - Validate API token scopes and ownership.
2. Check network security settings:
   - Navigate to **Security → Network → Network Zones**.
   - Review IP allowlists and trusted origins.
3. Validate certificate management:
   - Navigate to **Security → API → Tokens** and **Settings → Custom URLs** for SSL/TLS certificates.
4. Review feature release settings:
   - Navigate to **Settings → Customization → Features** for early-release features; ensure they align with stability and security policies.
5. Ensure logging and monitoring:
   - Confirm System Logs are forwarded to your SIEM or logging platform.
   - Verify alert rules for critical security events.
6. Incident response readiness:
   - Check alert notifications under **Settings → General → Security Notifications**.

### API Verification
```bash
# List network zones
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/zones" | jq > network_zones.json

# List API tokens
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/tokens?limit=200" | jq > api_tokens.json

# List signing keys
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/keys" | jq > signing_keys.json
```

### Best Practices Checklist
- [ ] Principle of least privilege enforced: minimal roles, scopes, and group assignments.
- [ ] Network zones and IP allowlists configured appropriately.
- [ ] API tokens are rotated regularly and scoped tightly.
- [ ] SSL/TLS certificates managed and renewed before expiration.
- [ ] System Logs are centralized, with alerts for critical events.
- [ ] Incident response procedures are documented and tested.
- [ ] Backup and recovery processes are in place.
- [ ] Regular user access reviews are conducted.
- [ ] Feature release and update settings are reviewed before enabling.
- [ ] Inline Hooks and custom integrations are audited for security.

## 17. DISA STIG Requirements

The Defense Information Systems Agency (DISA) has published Security Technical Implementation Guides (STIGs) specifically for Okta IDaaS. These STIGs provide detailed security configuration standards required for DOD implementations. The following section outlines the key STIG requirements organized by security domains.

### Session Management STIGs

#### V-273186: Global Session Timeout (15 minutes)
**Severity**: Medium  
**Requirement**: Okta must log out a session after a 15-minute period of inactivity.

**Admin Console Steps**:
1. Go to **Security → Global Session Policy**
2. Select the Default Policy
3. Add or edit a rule with:
   - Maximum Okta global session idle time: 15 minutes

#### V-273187: Admin Console Session Timeout (15 minutes)
**Severity**: Medium  
**Requirement**: The Okta Admin Console must log out a session after a 15-minute period of inactivity.

**Admin Console Steps**:
1. Go to **Applications → Applications → Okta Admin Console**
2. In the Sign On tab, under "Okta Admin Console session"
3. Set Maximum app session idle time: 15 minutes

#### V-273203: Global Session Lifetime (18 hours)
**Severity**: Medium  
**Requirement**: Okta must be configured to limit the global session lifetime to 18 hours.

**Admin Console Steps**:
1. Go to **Security → Global Session Policy**
2. In the rule configuration, set:
   - Maximum Okta global session lifetime: 18 hours

#### V-273206: Disable Persistent Session Cookies
**Severity**: Medium  
**Requirement**: Okta must be configured to disable persistent global session cookies.

**Admin Console Steps**:
1. Go to **Security → General**
2. Set "Okta global session cookies persist across browser sessions" to Disabled

### Account Management STIGs

#### V-273188: Automatic Account Disabling (35 days)
**Severity**: Medium  
**Requirement**: Okta must automatically disable accounts after a 35-day period of account inactivity.

**Admin Console Steps**:
1. Go to **Workflow → Automations**
2. Create automation with:
   - Condition: User Inactivity in Okta (35 days)
   - Action: Change User lifecycle state to Suspended
   - Schedule: Run Daily
   - Applies to: Everyone

#### V-273189: Account Lockout Policy
**Severity**: Medium  
**Requirement**: Okta must enforce the limit of three consecutive invalid login attempts by a user during a 15-minute time period.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each Password Policy:
   - Enable "Lock out after 3 unsuccessful attempts"

### Authentication Requirements STIGs

#### V-273190: Dashboard Phishing-Resistant Authentication
**Severity**: Medium  
**Requirement**: The Okta Dashboard application must be configured to allow authentication only via non-phishable authenticators.

**Admin Console Steps**:
1. Go to **Security → Authentication Policies**
2. Edit "Okta Dashboard" policy
3. In top rule, set:
   - Possession factor constraints: Phishing resistant (checked)

#### V-273191: Admin Console Phishing-Resistant Authentication
**Severity**: Medium  
**Requirement**: The Okta Admin Console application must be configured to allow authentication only via non-phishable authenticators.

**Admin Console Steps**:
1. Go to **Security → Authentication Policies**
2. Edit "Okta Admin Console" policy
3. In top rule, set:
   - Possession factor constraints: Phishing resistant (checked)

#### V-273193: Admin Console MFA
**Severity**: High  
**Requirement**: The Okta Admin Console application must be configured to use multifactor authentication.

**Admin Console Steps**:
1. Go to **Security → Authentication Policies**
2. Edit "Okta Admin Console" policy
3. Set "User must authenticate with":
   - "Password/IdP + Another factor" OR "Any 2 factor types"

#### V-273194: Dashboard MFA
**Severity**: High  
**Requirement**: The Okta Dashboard application must be configured to use multifactor authentication.

**Admin Console Steps**:
1. Go to **Security → Authentication Policies**
2. Edit "Okta Dashboard" policy
3. Set "User must authenticate with":
   - "Password/IdP + Another factor" OR "Any 2 factor types"

#### V-273204: PIV/CAC Authentication
**Severity**: Medium  
**Requirement**: Okta must be configured to accept Personal Identity Verification (PIV) credentials.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Verify "Smart Card Authenticator" is active
3. Configure with DOD-approved certificates

### Password Policy STIGs

#### V-273195: Minimum Password Length (15 characters)
**Severity**: Medium  
**Requirement**: Okta must enforce a minimum 15-character password length.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each policy, set:
   - Minimum Length: 15 characters

#### V-273196-V-273199: Password Complexity
**Severity**: Medium  
**Requirements**: Okta must enforce password complexity by requiring:
- At least one uppercase character (V-273196)
- At least one lowercase character (V-273197)
- At least one numeric character (V-273198)
- At least one special character (V-273199)

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each policy, enable:
   - Upper case letter (checked)
   - Lower case letter (checked)
   - Number (0-9) (checked)
   - Symbol (e.g., !@#$%^&*) (checked)

#### V-273200: Minimum Password Lifetime (24 hours)
**Severity**: Medium  
**Requirement**: Okta must enforce 24 hours/one day as the minimum password lifetime.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each policy, set:
   - Minimum password age: 24 hours

#### V-273201: Maximum Password Lifetime (60 days)
**Severity**: Medium  
**Requirement**: Okta must enforce a 60-day maximum password lifetime restriction.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each policy, set:
   - Password expires after: 60 days

#### V-273208: Common Password Check
**Severity**: Medium  
**Requirement**: Okta must validate passwords against a list of commonly used, expected, or compromised passwords.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each policy, enable:
   - Common Password Check

#### V-273209: Password History
**Severity**: Medium  
**Requirement**: Okta must prohibit password reuse for a minimum of five generations.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Password authenticator
3. For each policy, set:
   - Enforce password history for last: 5 passwords

### Security Configuration STIGs

#### V-273192: DOD Warning Banner
**Severity**: Medium  
**Requirement**: Okta must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the application.

**Implementation**: Follow the supplemental "Okta DOD Warning Banner Configuration Guide" provided with the STIG package.

#### V-273202: Audit Log Streaming
**Severity**: High  
**Requirement**: Okta must off-load audit records onto a central log server.

**Admin Console Steps**:
1. Go to **Reports → Log Streaming**
2. Configure one of:
   - AWS EventBridge integration
   - Splunk integration
   - External SIEM via API polling

**Alternative API Method**:
- Configure external SIEM to poll `/api/v1/logs` endpoint
- Ensure logs are collected at least every 5 minutes

#### V-273205: FIPS Compliance for Okta Verify
**Severity**: Medium  
**Requirement**: The Okta Verify application must be configured to connect only to FIPS-compliant devices.

**Admin Console Steps**:
1. Go to **Security → Authenticators**
2. Edit Okta Verify settings
3. Enable FIPS Compliance mode

#### V-273207: DOD-Approved Certificate Authorities
**Severity**: Medium  
**Requirement**: Okta must be configured to use only DOD-approved certificate authorities.

**Admin Console Steps**:
1. Go to **Security → Identity Providers**
2. For Smart Card IdP configuration:
   - Upload only DOD-approved CA certificates
   - Remove any non-DOD certificate authorities

### STIG Compliance Checklist Summary

Use this checklist to verify all DISA STIG requirements are met:

**Session Management**
- [ ] Global session timeout: 15 minutes inactive
- [ ] Admin Console timeout: 15 minutes inactive  
- [ ] Global session lifetime: 18 hours maximum
- [ ] Persistent cookies: Disabled

**Account Management**
- [ ] Automatic account disabling: 35 days
- [ ] Account lockout: 3 attempts

**Authentication**
- [ ] Dashboard: Phishing-resistant factors only
- [ ] Admin Console: Phishing-resistant factors only
- [ ] Dashboard: MFA required
- [ ] Admin Console: MFA required
- [ ] PIV/CAC: Smart Card enabled

**Password Policies**
- [ ] Minimum length: 15 characters
- [ ] Complexity: Upper, lower, number, symbol required
- [ ] Minimum age: 24 hours
- [ ] Maximum age: 60 days
- [ ] Common password check: Enabled
- [ ] Password history: 5 generations

**Security Configuration**
- [ ] DOD warning banner: Configured
- [ ] Audit logs: Streaming to SIEM
- [ ] Okta Verify: FIPS mode enabled
- [ ] Certificate authorities: DOD-approved only

### STIG Documentation Resources

The complete DISA STIG package includes:
- **U_Okta_IDaaS_STIG_V1R1_Manual-xccdf.xml**: Machine-readable STIG checklist
- **U_Okta_IDaaS_V1R1_Overview.pdf**: Overview and implementation guidance
- **U_Okta_IDaaS_DOD_Warning_Banner_Configuration_Guide_V1R1.pdf**: Detailed banner setup instructions
- **U_Okta_IDaaS_V1R1_Revision_History.pdf**: Version history and changes

For the latest STIG updates, visit: https://public.cyber.mil/stigs/

## Documentation Template

For each section evaluated, document:
1. **Current Configuration**: Findings from the Admin Console and API checks
2. **Compliance Status**: Compliant, Partially Compliant, Non-Compliant
3. **Gaps**: Any identified compliance gaps
4. **Recommendations**: Specific actions to address gaps
5. **Evidence**: Screenshots or API outputs demonstrating compliance

## Final Compliance Report

Compile your findings into a comprehensive compliance report that includes:
1. Executive summary
2. Scope of evaluation
3. Methodology
4. Detailed findings by section
5. Gap analysis
6. Remediation plan
7. Appendices with evidence