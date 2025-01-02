import argparse
import requests
import csv
import os
import sys
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Setup Colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

# Argument Parser
parser = argparse.ArgumentParser(description='Simplified IAM audit script')
parser.add_argument('-t', '--token', required=True, help=argparse.SUPPRESS)
args = parser.parse_args()

# Logging Setup
logging.basicConfig(level=logging.WARNING, filename='error.log', filemode='w',
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API Configuration
url_base = 'https://api.xdr.trendmicro.com'
iam_url_path = '/v3.0/iam/accounts'
audit_logs_url_path = '/v3.0/audit/logs'
headers = {'Authorization': 'Bearer ' + args.token, 'Content-Type': 'application/json'}

# Fetch IAM Accounts
def get_iam_accounts():
    accounts = []
    next_url = f"{url_base}{iam_url_path}?top=100"
    print(f"{GREEN}Fetching IAM accounts...{RESET}", end="")

    while next_url:
        response = requests.get(next_url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            accounts.extend(response_json.get('items', []))
            next_url = response_json.get('nextLink') or response_json.get('@odata.nextLink')
        else:
            logger.error(f"Error fetching IAM accounts: {response.status_code} - {response.text}")
            print(f"{RED}Error fetching IAM accounts. Check error.log{RESET}")
            sys.exit(1)

    print(f" {YELLOW}Total IAM accounts retrieved: {len(accounts)}{RESET}")
    return [{'UserId': a.get('email', 'Unknown'), 'RoleName': a.get('role', 'Unknown'), 'ID': a.get('id')} for a in accounts]

# Fetch Audit Logs and Extract Last Login
def get_last_logins():
    audit_logs = {}
    params = {'limit': 100}
    next_url = f"{url_base}{audit_logs_url_path}"
    print(f"{GREEN}Fetching audit logs...{RESET}", end="")
    total_logs = 0

    while next_url:
        response = requests.get(next_url, headers=headers, params=params)
        if response.status_code == 200:
            response_json = response.json()
            for log in response_json.get('items', []):
                details = log.get('details', {})
                identifier = details.get('identifier', {})

                # Handle missing or malformed 'identifier'
                if isinstance(identifier, str):
                    logger.warning(f"Unexpected string in 'identifier': {identifier}")
                    continue
                elif not isinstance(identifier, dict):
                    logger.warning(f"Malformed 'identifier' data: {details}")
                    continue

                user_id = identifier.get('id')
                activity = log.get('activity')
                log_date = log.get('loggedDateTime')

                if user_id and activity == 'Log on' and log_date:
                    # Keep only the most recent login
                    existing_date = audit_logs.get(user_id, {}).get('last_login')
                    if not existing_date or log_date > existing_date:
                        audit_logs[user_id] = {'last_login': log_date}

            total_logs += len(response_json.get('items', []))
            next_url = response_json.get('nextLink')
        else:
            logger.error(f"Error fetching audit logs: {response.status_code} - {response.text}")
            print(f"{RED}Error fetching audit logs. Check error.log{RESET}")
            break

    print(f" {YELLOW}Total audit logs retrieved: {total_logs}{RESET}")
    return audit_logs

# Check If User Has Logged In Within 90 Days
def has_logged_in_recently(last_login_date):
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    try:
        log_datetime = datetime.strptime(last_login_date, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        return log_datetime >= ninety_days_ago
    except Exception as e:
        logger.warning(f"Invalid date format: {last_login_date}, Error: {e}")
        return False

# Main Logic
def main():
    iam_accounts = get_iam_accounts()
    last_logins = get_last_logins()

    output_data = []
    total_accounts = len(iam_accounts)

    for i, account in enumerate(iam_accounts, 1):
        user_id = account.get('ID')
        if not user_id:
            logger.warning(f"Skipping account due to missing ID: {account}")
            continue

        last_login = last_logins.get(user_id, {}).get('last_login')
        if not last_login or not has_logged_in_recently(last_login):
            output_data.append({
                'UserId': account['UserId'],
                'RoleName': account['RoleName'],
                'RequestType': 'Remove'
            })
            if not last_login:
                logger.warning(f"No login activity found for user: {account['UserId']}")

    print(f"{GREEN}Processing complete.{RESET}")

    # Save to CSV
    if output_data:
        output_file = os.path.join(os.getcwd(), 'filtered_accounts_report.csv')
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['UserId', 'RoleName', 'RequestType']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_data)
        print(f"Filtered accounts saved to: {YELLOW}{os.path.abspath(output_file)}{RESET}")
    else:
        print(f"{RED}No accounts found that need to be removed.{RESET}")

    print(f"Total IAM accounts: {YELLOW}{len(iam_accounts)}{RESET}")
    print(f"Total accounts scheduled for removal: {YELLOW}{len(output_data)}{RESET}")
    print(f"{GREEN}Script execution completed successfully.{RESET}")

if __name__ == "__main__":
    main()

