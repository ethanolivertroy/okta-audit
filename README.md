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

### Automated vs Manual Checks
- **Automated**: ~85% of checks are automated via API
- **Manual Verification Required**:
  - DOD Warning Banner (V-273192)
  - Account inactivity automation workflows
  - FIPS compliance mode at platform level
  - Certificate authority validation

## API Permissions Required

The API token needs the following Okta permissions:
- Read access to policies (all types)
- Read access to authenticators
- Read access to users and groups
- Read access to applications
- Read access to identity providers
- Read access to system logs
- Read access to event hooks and log streams

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