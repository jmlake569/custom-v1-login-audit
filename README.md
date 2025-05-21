# Custom V1 Login Audit Report

This script generates a report of user login activities from Trend Vision One's audit logs. It identifies users who haven't logged in within the last 90 days and creates a CSV report for account cleanup.

## Features

- Fetches IAM accounts from Trend Vision One
- Retrieves login activity for each user
- Identifies inactive users (no login in 90 days)
- Generates a CSV report for account cleanup
- Handles API rate limits with exponential backoff
- Includes detailed logging and error handling

## Prerequisites

- Python 3.6 or higher
- Trend Vision One API token with appropriate permissions

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/custom-v1-login-audit.git
cd custom-v1-login-audit
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

Run the script with your Trend Vision One API token:

```bash
python login_audit_report.py -t YOUR_API_TOKEN
```

The script will:
1. Fetch all IAM accounts
2. Check login activity for each user
3. Generate a CSV report named `filtered_accounts_report.csv`

## Output

The script generates a CSV file with the following columns:
- `UserId`: User's email address
- `RoleName`: User's role in the system
- `RequestType`: Set to 'Remove' for accounts to be deactivated

## Error Handling

- Errors are logged to `error.log`
- Rate limit handling with exponential backoff
- Detailed console output for debugging

## API Details

The script uses the Trend Vision One API v3.0:
- Endpoint: `/v3.0/audit/logs`
- Filter: `(category eq 'Logon and Logoff')`
- Retention period: 180 days
- Rate limit: 500 requests per 60-second window

## Dependencies

The script requires the following Python packages:
- `requests`: For making HTTP requests to the Trend Vision One API
- `python-dateutil`: For handling date/time operations

These dependencies are listed in `requirements.txt` and can be installed using pip.

## Contributing

Feel free to submit issues and enhancement requests!
