# Okta FedRAMP Compliance Audit Tool

<img src="image.webp" width="600" alt="Okta Audit">

## Overview
- A comprehensive tool for evaluating Okta configurations for FedRAMP compliance and DISA STIG validation
- Aligns with NIST 800-53 controls for identity and access management
- Validates FIPS 140-2/140-3 cryptographic compliance for federal systems
- Available in both Bash and Python versions
- Built to support U.S. Federal security requirements and guidelines
- Thanks to https://developer.okta.com/ for their comprehensive API documentation

## Quick Start

### Python Version (Recommended)
```bash
# Install dependencies
pip install requests

# Run audit
./okta-audit.py -d your-org.okta.com -t YOUR_API_TOKEN
```

### Bash Version
```bash
# Ensure dependencies are installed: jq, zip, curl
./okta-audit.sh -d your-org.okta.com -t YOUR_API_TOKEN
```

## Features

### Comprehensive Data Collection
- Retrieves 40+ types of Okta configuration data via API
- Handles pagination and rate limiting automatically
- Supports both SSWS and OAuth 2.0 tokens

### Multi-Framework Compliance
- **FedRAMP (NIST 800-53)**: 20+ controls evaluated
- **DISA STIG V1R1**: 24 requirements checked
- **General Security**: Best practices assessment

### Intelligent Analysis
- Automated compliance checking (85% coverage)
- Risk-based authentication evaluation
- Inactive user detection
- Certificate/PIV/CAC authentication verification

### Detailed Reporting
- Executive summary with key findings
- Unified compliance matrix mapping controls across frameworks
- DISA STIG checklist with automated checks
- Quick reference guide for compliance teams

## Requirements

### Python Version (okta-audit.py)
- Python 3.6+
- `requests` library (`pip install requests`)

### Bash Version (okta-audit.sh)
- Bash 4+ (for associative arrays)
- jq (for JSON parsing)
- zip (for creating archives)
- curl (for API calls)

## Installation

1. Clone the repository:
   ```bash
   # From GitLab (primary)
   git clone https://gitlab.com/hackIDLE/fedramp/fedramp-testing-public/identity-and-access-management/okta-audit.git
   cd okta-audit
   
   # Or from GitHub mirror
   git clone https://github.com/ethanolivertroy/okta-audit.git
   cd okta-audit
   ```

2. Make scripts executable:
   ```bash
   chmod +x okta-audit.py okta-audit.sh
   ```

3. For Python version, install dependencies:
   ```bash
   pip install requests
   ```

## Usage

### Command Line Options

Both scripts support similar options:

```
-d, --domain DOMAIN       Your Okta domain (e.g., your-org.okta.com)
-t, --token TOKEN         Your Okta API token
-o, --output-dir DIR      Custom output directory (default: timestamped dir)
-p, --page-size SIZE      Number of items per page for API calls (default: 200)
-h, --help               Show help message and exit
```

Additional options for Python version:
```
--max-pages PAGES         Maximum number of pages to retrieve (default: 10)
--oauth                   Use OAuth 2.0 token instead of SSWS token
```

Additional options for Bash version:
```
-i, --interactive         Force interactive mode even if arguments provided
-n, --non-interactive     Use non-interactive mode with provided arguments
```

### Examples

1. Basic audit:
   ```bash
   # Python
   ./okta-audit.py -d mycompany.okta.com -t YOUR_API_TOKEN
   
   # Bash
   ./okta-audit.sh -d mycompany.okta.com -t YOUR_API_TOKEN
   ```

2. With custom output directory:
   ```bash
   ./okta-audit.py -d mycompany.okta.com -t YOUR_API_TOKEN -o audit_results
   ```

3. Using OAuth token (Python only):
   ```bash
   ./okta-audit.py -d mycompany.okta.com -t YOUR_OAUTH_TOKEN --oauth
   ```

4. Non-interactive mode (Bash only):
   ```bash
   ./okta-audit.sh -d mycompany.okta.com -t YOUR_API_TOKEN -n
   ```

## Output Structure

Both versions create a similar directory structure:

```
okta_audit_results_TIMESTAMP/
├── core_data/              # Raw API responses
│   ├── sign_on_policies.json
│   ├── password_policies.json
│   ├── authenticators.json
│   └── ... (25+ data files)
├── analysis/               # Processed data
│   ├── session_analysis.json
│   ├── password_policy_analysis.json
│   ├── inactive_users.json
│   └── ... (15+ analysis files)
├── compliance/             # Compliance reports
│   ├── executive_summary.md
│   ├── unified_compliance_matrix.md
│   ├── fips_compliance_report.txt
│   └── disa_stig/
│       └── stig_compliance_checklist.md
├── QUICK_REFERENCE.md      # Quick reference guide
└── validate_compliance.sh  # Validation script
```

## Compliance Coverage

### FedRAMP Controls (NIST 800-53)
- **Access Control**: AC-2, AC-2(3), AC-2(4), AC-2(12), AC-7, AC-8, AC-11, AC-12
- **Audit and Accountability**: AU-2, AU-3, AU-4, AU-6
- **Identification and Authentication**: IA-2, IA-2(1), IA-2(11), IA-5, IA-5(2)
- **System and Communications Protection**: SC-13
- **System and Information Integrity**: SI-4

### DISA STIG Requirements
- **Session Management**: V-273186, V-273187, V-273203, V-273206
- **Authentication Security**: V-273189, V-273190, V-273191, V-273193, V-273194
- **Password Policy**: V-273195 through V-273201, V-273208, V-273209
- **Logging and Monitoring**: V-273202
- **Advanced Authentication**: V-273204, V-273205, V-273207

### STIG Coverage Details

**Fully Automated (19/24):**
- ✅ All session management checks (V-273186, V-273187, V-273203, V-273206)
- ✅ All password policy checks (V-273195 through V-273201, V-273208, V-273209)
- ✅ MFA enforcement checks (V-273193, V-273194)
- ✅ Authentication security checks (V-273189, V-273190, V-273191)
- ✅ Log offloading check (V-273202)
- ✅ PIV/CAC support detection (V-273204)

**Partially Automated (4/24):**
- ⚠️ V-273188: We detect inactive users but can't verify automation workflows via API
- ⚠️ V-273205: We check Okta Verify settings but FIPS mode is a platform-level setting
- ⚠️ V-273207: We detect certificate IdPs but can't validate CA chains automatically

**Manual Only (1/24):**
- ❌ V-273192: DOD Warning Banner - this is a UI element that can't be checked via API


## API Permissions Required

### Creating a Read-Only API Token

1. Log in to your Okta Admin Console
2. Navigate to **Security** > **API** > **Tokens**
3. Click **Create Token**
4. Name your token (e.g., "Audit Script Read-Only")
5. Copy the token value immediately (it won't be shown again)

### Required Permissions

The API token needs the following Okta permissions for comprehensive auditing:

**User Management**
- `okta.users.read` - Read user profiles and status
- `okta.groups.read` - Read group memberships
- `okta.apps.read` - Read application assignments

**Authentication & Security**
- `okta.authenticators.read` - Read authenticator configurations
- `okta.authorizationServers.read` - Read authorization server settings
- `okta.idps.read` - Read identity provider configurations
- `okta.trustedOrigins.read` - Read trusted origins

**Policies**
- `okta.policies.read` - Read all policy types including:
  - Sign-on policies
  - Password policies
  - MFA enrollment policies
  - Access policies
  - User lifecycle policies
  - Authentication policies

**Logging & Monitoring**
- `okta.logs.read` - Read system logs
- `okta.eventHooks.read` - Read event hook configurations
- `okta.logStreams.read` - Read log streaming configurations

**System Configuration**
- `okta.orgs.read` - Read organization settings
- `okta.factors.read` - Read factor configurations
- `okta.deviceAssurance.read` - Read device assurance policies
- `okta.networkZones.read` - Read network zones
- `okta.behaviors.read` - Read behavior detection settings

### Using Admin Roles Instead

Alternatively, you can use an account with one of these read-only admin roles:
- **Read-Only Administrator** - Full read access to all Okta resources
- **Compliance Administrator** - Designed for compliance auditing
- **Report Administrator** - Access to reports and logs

### Token Security Best Practices

1. **Use a dedicated service account** for auditing rather than personal credentials
2. **Rotate tokens regularly** (recommended: every 90 days)
3. **Store tokens securely** using environment variables or secrets management
4. **Monitor token usage** through Okta system logs
5. **Revoke tokens immediately** when no longer needed

### Verifying Token Permissions

To verify your token has the correct permissions:
```bash
curl -X GET "https://your-org.okta.com/api/v1/users?limit=1" \
  -H "Authorization: SSWS YOUR_API_TOKEN" \
  -H "Accept: application/json"
```

If successful, you'll receive a JSON response. Common permission errors:
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Token lacks required permissions

## Key Reports

1. **Executive Summary** (`compliance/executive_summary.md`)
   - High-level overview of findings
   - Critical issues requiring attention
   - Compliance metrics and recommendations

2. **Unified Compliance Matrix** (`compliance/unified_compliance_matrix.md`)
   - Maps each check to FedRAMP and STIG controls
   - Shows where to find evidence for each requirement

3. **STIG Compliance Checklist** (`compliance/disa_stig/stig_compliance_checklist.md`)
   - Complete checklist of DISA STIG requirements
   - Indicates which checks are automated vs manual

4. **Quick Reference** (`QUICK_REFERENCE.md`)
   - Guide to understanding the output structure
   - Key files for compliance review

## Performance Considerations

- **API Calls**: ~40 endpoints queried
- **Rate Limiting**: Automatic handling with exponential backoff
- **Typical Runtime**: 2-5 minutes depending on org size
- **Large Organizations**: Increase page size limits if needed

## Differences Between Versions

### Python Version Advantages
- Better error handling and recovery
- Cross-platform compatibility (Windows, Mac, Linux)
- More robust rate limiting
- Easier to extend and maintain
- Cleaner code structure

### Bash Version Advantages
- No Python dependencies
- Native to most Unix/Linux systems
- Interactive mode for guided usage
- Slightly faster for small organizations

## Troubleshooting

1. **Authentication Errors**
   - Verify your API token has the required permissions
   - Ensure token format is correct (SSWS prefix for API tokens)
   - Check domain format (e.g., company.okta.com, not https://company.okta.com)

2. **Rate Limiting**
   - The scripts handle this automatically
   - For persistent issues, reduce `--page-size`
   - Consider running during off-peak hours

3. **Missing Data**
   - Some endpoints may not be available in all Okta editions
   - Check API permissions for your token
   - Review error messages in console output

4. **Large Organizations**
   - Increase `--max-pages` (Python) if you have many users/policies
   - Be patient - large orgs may take 5-10 minutes to audit

## License

This project is licensed under the GNU General Public License v3.0 - see the [COPYING](COPYING) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions:
- Primary repository: [GitLab](https://gitlab.com/hackIDLE/fedramp/fedramp-testing-public/identity-and-access-management/okta-audit)
- GitHub mirror: [ethanolivertroy/okta-audit](https://github.com/ethanolivertroy/okta-audit)

## Acknowledgments

- Thanks to the Okta team for their comprehensive API documentation
- Built to support U.S. Federal security requirements and guidelines
- Inspired by the need for automated compliance verification in federal environments