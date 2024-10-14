import os
import re
import csv
import requests
import logging
from pymisp import PyMISP, MISPEvent, MISPAttribute

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MISP configuration
MISP_URL = ""
MISP_KEY = ""
MISP_VERIFYCERT = True

CSV_URL = "https://tracker.viriback.com/last30.php"
TRACKED_URLS_FILE = "tracked_urls.txt"

# Tags
EVENT_TAGS = [
    "ViriBack C2 Tracker"
]

ATTRIBUTE_TAGS = [
    "C2"
]


def download_csv(csv_url):
    """Download the CSV file from the specified URL."""
    logging.info(f"Downloading CSV file from {csv_url}...")
    response = requests.get(csv_url)
    if response.status_code == 200:
        with open('c2servers.csv', 'wb') as file:
            file.write(response.content)
        logging.info("CSV file downloaded successfully.")
        return 'c2servers.csv'
    else:
        logging.error(f"Failed to download CSV. Status code: {response.status_code}")
        return None


def parse_csv(file_path):
    """Parse the CSV and extract the relevant fields (1st and 2nd values)."""
    extracted_data = []
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) >= 2:
                name, url = row[0].strip(), row[1].strip()  # Strip any extra whitespace
                extracted_data.append((name, url))
            else:
                logging.debug(f"Skipping invalid row: {row}")
    return extracted_data


def init_misp():
    """Initialize MISP connection."""
    try:
        return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    except Exception as e:
        logging.error(f"Failed to initialize MISP connection: {e}")
        exit(1)


def create_misp_event(misp):
    """Create a MISP event and return the event ID."""
    try:
        event = MISPEvent()
        event.info = f"ViriBack C2 Admin Panel Tracker"
        event.distribution = 1
        event.threat_level_id = 2
        event.analysis = 0

        # Add event-level tags
        for tag in EVENT_TAGS:
            event.add_tag(tag)

        result = misp.add_event(event)
        if 'Event' in result:
            event_id = result['Event']['id']
            logging.info(f"MISP Event created with ID: {event_id}")
            print(f"MISP Event created successfully with ID: {event_id}")
            return event_id
        else:
            logging.error("Failed to create MISP event.")
            print("Failed to create MISP event.")
            return None
    except Exception as e:
        logging.error(f"An error occurred while creating MISP event: {e}")
        print(f"An error occurred while creating MISP event: {e}")
        return None


def add_attribute_to_event(misp, event_id, comment, url):
    """Add the URL as an attribute to the MISP event with a comment and tag it."""
    try:
        attribute = MISPAttribute()
        attribute.type = "url"
        attribute.value = url
        attribute.comment = comment  # Add comment from CSV's first value

        # Add attribute-level tags
        for tag in ATTRIBUTE_TAGS:
            attribute.add_tag(tag)

        result = misp.add_attribute(event_id, attribute)

        if isinstance(result, dict) and 'Attribute' in result:
            logging.info(f"Added URL '{url}' with comment '{comment}' to MISP event {event_id}")
            print(f"Added URL '{url}' with comment '{comment}' to MISP event {event_id}")
        else:
            logging.error(f"Failed to add URL '{url}' to MISP event. Result: {result}")
            print(f"Failed to add URL '{url}' to MISP event. Result: {result}")
    except Exception as e:
        logging.error(f"Error adding URL '{url}' to MISP event: {e}")
        print(f"Error adding URL '{url}' to MISP event: {e}")


def is_valid_url(value):
    """Check if the value is a valid URL (not just an IP address)."""
    # Regular expression to identify IP addresses
    ip_regex = re.compile(r'^http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    # Check if the value contains a URL path or port, and is not just an IP address
    if ip_regex.match(value):
        return False  # It's just an IP address, so it's not a valid URL for our needs
    return True


def load_tracked_urls():
    """Load previously tracked URLs from a file."""
    if os.path.exists(TRACKED_URLS_FILE):
        with open(TRACKED_URLS_FILE, 'r') as file:
            return set(line.strip() for line in file)  # Strip whitespace and store unique URLs
    return set()


def save_tracked_urls(tracked_urls):
    """Save tracked URLs to a file."""
    with open(TRACKED_URLS_FILE, 'w') as file:
        for url in sorted(tracked_urls):  # Sort to keep order consistent
            file.write(f"{url}\n")


def cleanup_files():
    """Cleanup any temporary files used for tracking."""
    logging.info(f"Tracking file {TRACKED_URLS_FILE} preserved.")


def main():
    try:
        # Step 1: Load previously tracked URLs
        tracked_urls = load_tracked_urls()
        logging.info(f"Loaded {len(tracked_urls)} tracked URLs.")

        # Step 2: Download CSV
        csv_file_path = download_csv(CSV_URL)
        if not csv_file_path:
            print("CSV download failed. Exiting...")
            return

        # Step 3: Parse CSV
        parsed_data = parse_csv(csv_file_path)
        logging.info(f"Parsed {len(parsed_data)} rows from CSV.")
        print(f"Parsed {len(parsed_data)} rows from CSV.")

        # Step 4: Initialize MISP connection
        misp = init_misp()

        # Step 5: Check for new attributes to add
        new_urls = []
        for name, url in parsed_data:
            # Remove extra whitespace from URL and compare with tracked URLs
            url = url.strip()

            if url in tracked_urls:
                logging.info(f"Skipping already tracked URL: {url}")
                print(f"Skipping already tracked URL: {url}")
                continue  # Skip if the URL is already tracked

            if is_valid_url(url):
                new_urls.append((name, url))  # Collect new URLs for later processing

        # Step 6: Create MISP event only if there are new attributes
        if new_urls:
            event_id = create_misp_event(misp)
            if not event_id:
                print("Failed to create MISP event. Exiting...")
                return

            # Step 7: Add new attributes to MISP event
            for name, url in new_urls:
                add_attribute_to_event(misp, event_id, name, url)

            # Step 8: Update tracked URLs
            tracked_urls.update(url for _, url in new_urls)
            save_tracked_urls(tracked_urls)

            logging.info(f"Completed processing CSV for MISP event {event_id}.")
            print(f"Completed processing CSV for MISP event {event_id}.")
        else:
            logging.info("No new URLs to add. Skipping MISP event creation.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
