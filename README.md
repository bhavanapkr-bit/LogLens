
# LogLens — Web Log Threat Analyzer

LogLens is a Python and Streamlit application that analyzes Apache/Nginx access logs and highlights potentially suspicious web requests.

## Features

- Upload Apache/Nginx access log files.
- Parse IP addresses, timestamps, HTTP methods, paths, status codes, and user agents.
- Detect suspicious patterns using a JSON signature database.
- Identify possible brute-force activity using repeated HTTP 401 responses.
- Display request statistics and suspicious requests.
- Visualize attack activity by hour.
- Display top suspicious IP addresses.
- Export analysis results as CSV.
- Show illustrative map points when real IP locations are unavailable.

## Test Files

- `sample.log` — Sample log data for testing.
- `empty.log` — Tests how LogLens handles an empty file.
- `malformed.log` — Tests how LogLens handles incorrectly formatted log lines.

## Technologies Used

- Python
- Streamlit
- Pandas
- GeoLite2 City database
- GeoIP2 Python library
- JSON-based detection signatures

## Installation

1. Install Python.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Install the dependencies:

   `python -m pip install -r requirements.txt`

5. Run the application:

   `python -m streamlit run loglens.py`

6. Open the local URL shown in the terminal.

## GeoIP Database

To enable IP geolocation lookups, obtain the GeoLite2 City database from MaxMind and place the `.mmdb` file at the path configured in `loglens.py`.

Do not upload the database, license keys, or other private credentials to GitHub.

Some IP addresses, including private and reserved example addresses, do not have public geographic locations. Illustrative demo map points must not be interpreted as actual attacker locations.

## Performance Note

The parser reads log files line by line. However, the current dashboard stores parsed records in a list and a Pandas DataFrame. Large-file memory optimization and performance testing are still required before claiming support for 500 MB logs.

## Security Disclaimer

Detection results are indicators for investigation, not proof of malicious activity. Use LogLens only with logs you are authorized to analyze.
