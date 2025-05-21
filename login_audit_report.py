import argparse
import requests
import csv
import os
import sys
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from time import sleep
import json

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
headers = {
    'Authorization': 'Bearer ' + args.token,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

# Progress Bar Function
def display_progress(current, total, prefix="Progress"):
    progress = (current / total) * 100 if total else 100
    bar = '.' * int(progress // 2) + ' ' * (50 - int(progress // 2))
    sys.stdout.write(f"\r{GREEN}{prefix}: [{bar}] {current}/{total} ({progress:.2f}%){RESET}")
    sys.stdout.flush()

# Fetch IAM Accounts
def get_iam_accounts():
    accounts = []
    next_url = f"{url_base}{iam_url_path}?top=100"
    print(f"{GREEN}Fetching IAM accounts...{RESET}")

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

    print(f"Total IAM accounts retrieved: {YELLOW}{len(accounts)}{RESET}")
    return [{'UserId': a.get('email', 'Unknown'), 'RoleName': a.get('role', 'Unknown'), 'ID': a.get('id')} for a in accounts]

# Fetch Audit Logs and Extract Last Login
def get_last_logins():
    audit_logs = {}
    total_fetched = 0  # Tracks total fetched logs
    
    # Get IAM accounts first
    iam_accounts = get_iam_accounts()
    total_accounts = len(iam_accounts)

    # First, let's try to get ALL login activities to verify the API works
    print(f"\n{YELLOW}Testing API with a simple filter first...{RESET}")
    test_params = {
        'top': 10,  # Just get 10 records to test
        'orderBy': 'loggedDateTime desc',
        'labels': 'all'
    }
    
    test_headers = headers.copy()
    test_headers['TMV1-Filter'] = "(category eq 'Logon and Logoff')"
    
    test_url = f"{url_base}{audit_logs_url_path}"
    print(f"Test URL: {test_url}")
    print(f"Test Headers: {test_headers}")
    print(f"Test Params: {test_params}")
    
    try:
        test_response = requests.get(test_url, headers=test_headers, params=test_params)
        print(f"\nTest Response Status: {test_response.status_code}")
        print(f"Test Response Headers: {dict(test_response.headers)}")
        
        if test_response.status_code == 200:
            test_json = test_response.json()
            test_items = test_json.get('items', [])
            print(f"\nFound {len(test_items)} test records")
            if test_items:
                print(f"Sample test record structure:")
                print(json.dumps(test_items[0], indent=2))
        else:
            print(f"Test request failed: {test_response.text}")
    except Exception as e:
        print(f"Test request failed with error: {str(e)}")

    # Now proceed with per-user queries
    for i, account in enumerate(iam_accounts, 1):
        user_id = account.get('ID')
        if not user_id:
            continue

        # Set up query parameters
        params = {
            'top': 100,
            'orderBy': 'loggedDateTime desc',
            'labels': 'all'
        }
        
        # Set up filter in headers for this specific user's login activities
        request_headers = headers.copy()
        # Use loggedUser for the user's email
        filter_query = f"(category eq 'Logon and Logoff') and (loggedUser eq '{account['UserId']}')"
        request_headers['TMV1-Filter'] = filter_query
        
        next_url = f"{url_base}{audit_logs_url_path}"
        print(f"\n{YELLOW}Fetching login activities for user {account['UserId']}...{RESET}")
        print(f"Filter: {filter_query}")
        print(f"URL: {next_url}")
        print(f"Headers: {request_headers}")
        print(f"Params: {params}")

        max_retries = 3
        retry_count = 0
        base_delay = 10  # Start with 10 second delay

        while next_url and retry_count < max_retries:
            try:
                response = requests.get(next_url, headers=request_headers, params=params)
                print(f"\nResponse Status: {response.status_code}")
                print(f"Response Headers: {dict(response.headers)}")
                
                if response.status_code == 200:
                    response_json = response.json()
                    batch_logs = response_json.get('items', [])
                    total_fetched += len(batch_logs)
                    
                    print(f"Found {len(batch_logs)} logs in this batch")
                    if batch_logs:
                        print(f"Sample log: {json.dumps(batch_logs[0], indent=2)}")
                    else:
                        print(f"Response content: {json.dumps(response_json, indent=2)}")
                    
                    if not batch_logs:
                        print(f"{YELLOW}No logs found for user {account['UserId']}{RESET}")
                        logger.warning(f"No login activity found for user: {account['UserId']}")
                    else:
                        for log in batch_logs:
                            log_date = log.get('loggedDateTime')
                            if log_date:
                                # Only keep the most recent login
                                existing_date = audit_logs.get(user_id, {}).get('last_login')
                                if not existing_date or log_date > existing_date:
                                    audit_logs[user_id] = {'last_login': log_date}
                                    print(f"{GREEN}Found login for {account['UserId']}: {log_date}{RESET}")

                    next_url = response_json.get('nextLink')
                    if next_url:
                        print(f"{YELLOW}Fetching next page...{RESET}")
                        sleep(1)  # Add a small delay between requests
                    retry_count = 0  # Reset retry count on success
                elif response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', base_delay))
                    delay = retry_after * (2 ** retry_count)  # Exponential backoff
                    print(f"{YELLOW}Rate limit hit. Waiting {delay} seconds before retry {retry_count + 1}/{max_retries}...{RESET}")
                    sleep(delay)
                    retry_count += 1
                else:
                    error_message = f"Error fetching audit logs for user {account['UserId']}: {response.status_code} - {response.text}"
                    print(f"\n{RED}{error_message}{RESET}")
                    logger.error(error_message)
                    # Print the full response for debugging
                    print(f"Full response: {response.text}")
                    break
            except Exception as e:
                error_message = f"Exception while fetching logs for user {account['UserId']}: {str(e)}"
                print(f"\n{RED}{error_message}{RESET}")
                logger.error(error_message)
                break

        if retry_count >= max_retries:
            print(f"{RED}Max retries reached for user {account['UserId']}. Moving to next user.{RESET}")
            logger.error(f"Max retries reached for user {account['UserId']}")

        # Update progress
        print(f"{YELLOW}Processed {i}/{total_accounts} users{RESET}")

    print(f"\n{YELLOW}Total audit logs retrieved: {total_fetched}{RESET}")
    print(f"{YELLOW}Total unique users with login data: {len(audit_logs)}{RESET}")
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
