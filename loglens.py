import streamlit as st
import pandas as pd
from collections import Counter
import re
import json
import geoip2.database
from pathlib import Path
from parser import iter_log_records

import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO 
import sqlite3
import tempfile
import os
import shutil

@st.cache_resource
def get_job_manager():
    return {
        "executor": ThreadPoolExecutor(max_workers=2),
        "jobs": {},
        "lock": threading.Lock()
    }



def process_log_job(job_id, input_path, manager):
    db_path = None

    with manager["lock"]:
        manager["jobs"][job_id]["status"] = "Processing"

    try:
        fd, db_path = tempfile.mkstemp(
            prefix=f"loglens_{job_id}_",
            suffix=".db"
        )
        os.close(fd)

        valid_records = 0
        batch = []

        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE records (
                    id INTEGER PRIMARY KEY,
                    record_json TEXT NOT NULL
                )
            """)

            with open(input_path, "rb") as log_file:
                for record in iter_log_records(log_file):
                    batch.append((json.dumps(record),))
                    valid_records += 1

                    if len(batch) >= 1000:
                        conn.executemany(
                            "INSERT INTO records (record_json) VALUES (?)",
                            batch
                        )
                        conn.commit()
                        batch.clear()

                if batch:
                    conn.executemany(
                        "INSERT INTO records (record_json) VALUES (?)",
                        batch
                    )
                    conn.commit()

        with manager["lock"]:
            manager["jobs"][job_id]["db_path"] = db_path
            manager["jobs"][job_id]["valid_records"] = valid_records
            manager["jobs"][job_id]["status"] = "Completed"

    except Exception as error:
        if db_path and os.path.exists(db_path):
            os.remove(db_path)

        with manager["lock"]:
            manager["jobs"][job_id]["status"] = "Failed"
            manager["jobs"][job_id]["error"] = str(error)

    finally:
        if os.path.exists(input_path):
            os.remove(input_path)



GEOIP_DB = Path(__file__).parent / "GeoLite2-City_20261009" / "GeoLite2-City.mmdb"


def get_ip_location(ip):
    """Return approximate coordinates for a public IP address."""
    try:
        with geoip2.database.Reader(str(GEOIP_DB)) as reader:
            response = reader.city(ip)
            latitude = response.location.latitude
            longitude = response.location.longitude

            if latitude is None or longitude is None:
                return None

            return {
                "IP Address": ip,
                "Latitude": latitude,
                "Longitude": longitude
            }

    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None
    except Exception:
        return None


SIGNATURES_FILE = Path(__file__).parent / "signatures.json"


def load_signatures():
    """Load attack signatures from the JSON database."""
    try:
        with SIGNATURES_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        signatures = data.get("signatures", [])

        for signature in signatures:
            re.compile(signature["pattern"])

        return signatures

    except (OSError, json.JSONDecodeError, KeyError, TypeError, re.error) as error:
        st.error(f"Could not load attack signatures: {error}")
        return []


SIGNATURES = load_signatures()


st.set_page_config(
    page_title="LogLens - Security Log Analyzer",
    page_icon="🔍",
    layout="wide"
)

# ================= CYBER NEON THEME =================
st.markdown("""
<style>
/* Colour palette */
:root {
    --neon-bg: #080B14;
    --neon-card: #111827;
    --neon-cyan: #00F5FF;
    --neon-magenta: #FF2BD6;
    --neon-green: #39FF14;
    --neon-warning: #FF4500;
    --neon-text: #E5E7EB;
}

/* Main app background and text */
.stApp {
    background-color: var(--neon-bg);
    color: var(--neon-text);
}

[data-testid="stHeader"] {
    background: rgba(8, 11, 20, 0.95);
}

[data-testid="stSidebar"] {
    background-color: var(--neon-card);
    border-right: 1px solid var(--neon-cyan);
}

[data-testid="stMarkdownContainer"] p,
[data-testid="stCaptionContainer"],
label {
    color: var(--neon-text);
}

/* Main title and section headings */
h1, h2, h3 {
    color: var(--neon-cyan) !important;
}

h1 {
    text-shadow: 0 0 12px rgba(0, 245, 255, 0.35);
}

h2, h3 {
    text-shadow: 0 0 7px rgba(0, 245, 255, 0.18);
}

/* Panels and metric cards */
[data-testid="stMetric"] {
    background: var(--neon-card);
    border: 1px solid rgba(0, 245, 255, 0.55);
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 0 12px rgba(0, 245, 255, 0.08);
}

[data-testid="stMetricLabel"] {
    color: var(--neon-cyan) !important;
}

[data-testid="stMetricValue"] {
    color: var(--neon-text) !important;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button {
    background: var(--neon-card);
    color: var(--neon-cyan);
    border: 1px solid var(--neon-cyan);
    border-radius: 9px;
    font-weight: 600;
    transition: all 0.2s ease;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: var(--neon-cyan);
    color: var(--neon-bg);
    border-color: var(--neon-cyan);
    box-shadow: 0 0 14px rgba(0, 245, 255, 0.45);
}

/* File uploader */
[data-testid="stFileUploader"] {
    background: var(--neon-card);
    border: 1px dashed var(--neon-cyan);
    border-radius: 12px;
    padding: 12px;
}

/* Tables */
[data-testid="stDataFrame"],
[data-testid="stTable"] {
    border: 1px solid rgba(0, 245, 255, 0.35);
    border-radius: 8px;
    overflow: hidden;
}

/* Inputs, dropdowns and text fields */
[data-baseweb="select"] > div,
[data-baseweb="input"] > div {
    background-color: var(--neon-card);
    border-color: rgba(0, 245, 255, 0.5);
}

[data-baseweb="popover"] {
    background-color: var(--neon-card);
}

/* Status messages */
[data-testid="stAlert"] {
    background-color: var(--neon-card);
    border-radius: 9px;
}

/* Success = neon green */
[data-testid="stAlert"][kind="success"] {
    border-left: 4px solid var(--neon-green);
}

/* Warning/error = orange-red */
[data-testid="stAlert"][kind="warning"],
[data-testid="stAlert"][kind="error"] {
    border-left: 4px solid var(--neon-warning);
}

/* Info accents = magenta */
[data-testid="stAlert"][kind="info"] {
    border-left: 4px solid var(--neon-magenta);
}

/* Progress bars and sliders */
[data-testid="stProgress"] > div > div {
    background-color: var(--neon-cyan);
}

/* Dividers */
hr {
    border-color: rgba(0, 245, 255, 0.35);
}

/* Links */
a {
    color: var(--neon-magenta) !important;
}

/* Focus indicators */
*:focus-visible {
    outline: 2px solid var(--neon-cyan) !important;
    outline-offset: 2px;
}

/* Pink and orange neon accents */
[data-testid="stMetric"]:nth-of-type(even) {
    border-color: #FF2BD6;
    box-shadow: 0 0 12px rgba(255, 43, 214, 0.12);
}

[data-testid="stMetric"]:nth-of-type(even) [data-testid="stMetricLabel"] {
    color: #FF2BD6 !important;
}

[data-testid="stAlert"][kind="info"] {
    border-left: 4px solid #FF2BD6 !important;
}

[data-testid="stAlert"][kind="warning"],
[data-testid="stAlert"][kind="error"] {
    border-left: 4px solid #FF4500 !important;
}

[data-testid="stProgress"] > div > div {
    background: linear-gradient(90deg, #00F5FF, #FF2BD6, #FF4500);
}

</style>
""", unsafe_allow_html=True)
# =============== END CYBER NEON THEME ===============

st.title("🔍 LogLens")
st.subheader("Security Log Analysis Dashboard")
st.write(
    "Upload an Apache or Nginx access log to analyze requests "
    "and identify potentially suspicious activity."
)


col_upload, col_demo = st.columns(2)

with col_upload:
    uploaded_file = st.file_uploader(
        "Upload a log file",
        type=["log", "txt"],
        max_upload_size=500
    )

with col_demo:
    st.write("Try LogLens with a sample")
    load_demo = st.button("🧪 Load Demo Log", use_container_width=True)

if load_demo:
    demo_path = Path(__file__).parent / "sample.log"
    if demo_path.exists():
        uploaded_file = demo_path.open("rb")
        st.session_state["demo_log_content"] = uploaded_file.read()
        uploaded_file.close()
    else:
        st.error("sample.log was not found in the project folder.")

if "demo_log_content" in st.session_state:
    from io import BytesIO
    uploaded_file = BytesIO(st.session_state["demo_log_content"])
    uploaded_file.name = "sample.log"



manager = get_job_manager()



def show_large_log_dashboard(db_path):
    """Analyse SQLite records in batches instead of loading the whole log."""

    batch_size = 1000
    ip_counts = Counter()
    unauthorized_counts = Counter()
    hourly_attacks = Counter()
    status_counts = Counter()
    suspicious_rows = []
    total = 0
    flagged = 0
    unique_ips = set()

    def detect_attack(record):
        path = str(record.get("Path", ""))

        for signature in SIGNATURES:
            if re.search(signature["pattern"], path):
                return (
                    signature["name"],
                    signature["type"],
                    signature["severity"],
                )

        return "None", "none", "low"

    with sqlite3.connect(db_path) as conn:
        # Pass 1: count requests and unauthorized responses.
        cursor = conn.execute(
            "SELECT record_json FROM records ORDER BY id"
        )

        while True:
            batch = cursor.fetchmany(batch_size)
            if not batch:
                break

            for (raw_record,) in batch:
                record = json.loads(raw_record)
                ip = str(record.get("IP Address", "Unknown"))

                total += 1
                unique_ips.add(ip)
                ip_counts[ip] += 1

                try:
                    status = int(record.get("Status Code", 0))
                except (ValueError, TypeError):
                    status = 0
                status_counts[status] += 1

                if status == 401:
                    unauthorized_counts[ip] += 1

        brute_force_ips = {
            ip for ip, count in unauthorized_counts.items()
            if count >= 5
        }

        # Pass 2: detect attacks and build summaries.
        cursor = conn.execute(
            "SELECT record_json FROM records ORDER BY id"
        )

        while True:
            batch = cursor.fetchmany(batch_size)
            if not batch:
                break

            for (raw_record,) in batch:
                record = json.loads(raw_record)
                ip = str(record.get("IP Address", "Unknown"))

                attack, category, severity = detect_attack(record)
                is_flagged = category != "none"

                if ip in brute_force_ips:
                    attack = "Possible Brute Force"
                    category = "brute_force"
                    severity = "high"
                    is_flagged = True

                if not is_flagged:
                    continue

                flagged += 1

                if len(suspicious_rows) < 1000:
                    suspicious_rows.append({
                        "IP Address": ip,
                        "Path": record.get("Path", ""),
                        "Attack Type": attack,
                        "Attack Category": category,
                        "Severity": severity,
                        "Status Code": record.get("Status Code", ""),
                    })

                timestamp = pd.to_datetime(
                    record.get("Timestamp", ""),
                    format="%d/%b/%Y:%H:%M:%S %z",
                    errors="coerce",
                )

                if not pd.isna(timestamp):
                    hour = timestamp.strftime("%Y-%m-%d %H:00")
                    hourly_attacks[hour] += 1

    # Summary cards
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", total)
    c2.metric("Unique IPs", len(unique_ips))
    c3.metric("Flagged Requests", flagged)
    c4.metric(
        "Error Responses",
        sum(
            count for status, count in status_counts.items()
            if status >= 400
        ),
    )

    st.info(
        "Large-log mode: records are read in batches. "
        "The suspicious-request table shows at most 1,000 rows."
    )

    st.subheader("📊 Requests by IP Address")
    top_ips = ip_counts.most_common(20)
    if top_ips:
        st.bar_chart(
            pd.DataFrame(
                top_ips, columns=["IP Address", "Requests"]
            ).set_index("IP Address")
        )

    st.subheader("🚨 Top Attackers")
    if suspicious_rows:
        suspicious_df = pd.DataFrame(suspicious_rows)

        top_attackers = (
            suspicious_df["IP Address"]
            .value_counts()
            .head(5)
            .rename_axis("IP Address")
            .reset_index(name="Suspicious Requests")
        )
        st.dataframe(top_attackers, hide_index=True)

        st.subheader("🚨 Potentially Suspicious Requests")
        st.dataframe(suspicious_df, hide_index=True)
    else:
        st.success("No requests matched the current detection rules.")

    st.subheader("⏰ Attacks by Hour")
    if hourly_attacks:
        timeline = pd.Series(hourly_attacks).sort_index()
        st.line_chart(timeline)
    else:
        st.info("No flagged requests with valid timestamps were found.")

    st.caption(
        "Detection results are indicators for review, not proof of an attack."
    )


if st.button("♻️ Recover Previous Large-Log Results"):
    temp_dir = Path(tempfile.gettempdir())
    candidates = []

    for db_file in temp_dir.glob("loglens_*.db"):
        try:
            with sqlite3.connect(
                db_file.as_uri() + "?mode=ro",
                uri=True,
                timeout=3,
            ) as conn:
                table = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='records'"
                ).fetchone()

                if table:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM records"
                    ).fetchone()[0]

                    if count > 0:
                        candidates.append(
                            (db_file.stat().st_mtime, db_file, count)
                        )
        except (sqlite3.Error, OSError):
            continue

    if not candidates:
        st.error("No saved LogLens results were found.")
    else:
        _, recovery_db, record_count = max(
            candidates, key=lambda item: item[0]
        )
        st.info(
            f"Recovering {record_count:,} saved records "
            f"from {recovery_db.name}"
        )
        show_large_log_dashboard(str(recovery_db))
        st.stop()


if uploaded_file:
    st.caption(f"Selected file: {uploaded_file.name}")

    if st.button("🚀 Start Analysis"):
        fd, input_path = tempfile.mkstemp(
            prefix="loglens_upload_",
            suffix=".log"
        )

        try:
            with os.fdopen(fd, "wb") as destination:
                uploaded_file.seek(0)
                shutil.copyfileobj(uploaded_file, destination)
        except Exception:
            if os.path.exists(input_path):
                os.remove(input_path)
            raise

        job_id = str(uuid.uuid4())[:8]

        with manager["lock"]:
            manager["jobs"][job_id] = {
                "status": "Queued",
                "db_path": None,
                "valid_records": 0,
                "error": None,
            }

        manager["executor"].submit(
            process_log_job,
            job_id,
            input_path,
            manager,
        )

        st.session_state["active_job_id"] = job_id


    active_job_id = st.session_state.get("active_job_id")

    if active_job_id:
        with manager["lock"]:
            job = manager["jobs"].get(active_job_id, {}).copy()

        if not job:
            st.warning("Job not found. Please start the analysis again.")
            st.stop()

        st.write(f"**Job ID:** `{active_job_id}`")
        st.write(f"**Status:** {job["status"]}")

        if job["status"] == "Failed":
            st.error(job.get("error") or "Processing failed.")
            st.stop()

        elif job["status"] == "Completed":
            st.success(
                f"Processing completed! "
                f"Valid records: {job['valid_records']}"
            )

            db_path = job.get("db_path")

            if not db_path or not os.path.exists(db_path):
                st.error("The processed database could not be found.")
                st.stop()

           
            if job["valid_records"] > 100000:
                show_large_log_dashboard(db_path)
                st.stop()

            # Keep the existing dashboard for smaller files.
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute(
                    "SELECT record_json FROM records ORDER BY id"
                ).fetchall()

            records = [json.loads(row[0]) for row in rows]


        elif job["status"] in ("Queued", "Processing"):
            if st.button("🔄 Refresh Job Status"):
                st.rerun()
            st.stop()

    else:
        st.info("Click Start Analysis to create a job.")
        st.stop()



    if not records:
        st.warning("No valid log records found.")
    else:
        df = pd.DataFrame(records)

        
        # Detect suspicious activity
        def detect_attack(path):
            
            for signature in SIGNATURES:
                if re.search(signature["pattern"], str(path)):
                    return (
                        signature["name"],
                        signature["type"],
                        signature["severity"]
                    )

            return ("None", "none", "low")
        
        detection_results = df["Path"].apply(detect_attack)

        df[["Attack Type", "Attack Category", "Severity"]] = pd.DataFrame(
            detection_results.tolist(),
            index=df.index
        )

        df["Flag"] = df["Attack Category"] != "none"

        # Detect possible brute-force activity
        unauthorized_counts = (
            df.loc[df["Status Code"] == 401, "IP Address"]
            .value_counts()
        )

        brute_force_ips = set(
            unauthorized_counts[unauthorized_counts >= 5].index
        )

        df.loc[
            df["IP Address"].isin(brute_force_ips), "Attack Type"
        ] = "Possible Brute Force"

        df.loc[
            df["IP Address"].isin(brute_force_ips), "Attack Category"
        ] = "brute_force"

        df.loc[
            df["IP Address"].isin(brute_force_ips), "Severity"
        ] = "high"

        df.loc[
            df["IP Address"].isin(brute_force_ips), "Flag"
        ] = True

        ip_counts = Counter(df["IP Address"])

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", len(df))
        col2.metric("Unique IPs", df["IP Address"].nunique())
        col3.metric("Flagged Requests", int(df["Flag"].sum()))
        col4.metric(
            "Error Responses",
            int((df["Status Code"] >= 400).sum())
        )

        st.divider()

        st.subheader("📊 Requests by IP Address")

        ip_df = (
            df["IP Address"]
            .value_counts()
            .rename_axis("IP Address")
            .reset_index(name="Requests")
        )

        st.bar_chart(ip_df.set_index("IP Address"))
        
        st.subheader("🚨 Top Attackers")

        suspicious_df = df[df["Flag"]]

        if suspicious_df.empty:
            st.info("No suspicious IP addresses found.")
        else:
            top_ips = (
                suspicious_df["IP Address"]
                .value_counts()
                .head(5)
                .rename_axis("IP Address")
                .reset_index(name="Suspicious Requests")
            )

            st.dataframe(
                top_ips,
                use_container_width=True,
                hide_index=True
            )

        # GeoIP attacker location map
        st.subheader("🌍 Attacker Locations")

        location_rows = []

        for ip in suspicious_df["IP Address"].unique():
            location = get_ip_location(ip)

            if location is not None:
                location_rows.append(location)

        if location_rows:
            location_df = pd.DataFrame(location_rows)

            st.map(
                location_df,
                latitude="Latitude",
                longitude="Longitude"
            )
       
            
        else:
            st.info(
                "The log contains private or unlocated IP addresses. "
                "The points below are illustrative demo locations, "
                "not actual attacker locations."
            )

            demo_map = pd.DataFrame({
                "Latitude": [13.0827, 12.9716, 17.3850],
                "Longitude": [80.2707, 77.5946, 78.4867]
            })

            st.map(
                demo_map,
                latitude="Latitude",
                longitude="Longitude"
            )



        st.subheader("🚨 Potentially Suspicious Requests")

        suspicious_df = df[df["Flag"]]

        if suspicious_df.empty:
            st.success(
                "No requests matched the current detection rules."
            )
        else:
            display_columns = [
                "IP Address",
                "Path",
                "Attack Type",
                "Attack Category",
                "Severity",
                "Status Code"
            ]

            st.dataframe(
                suspicious_df[display_columns],
                use_container_width=True,
                hide_index=True
            )

        # Attacks by hour
        st.subheader("⏰ Attacks by Hour")

        df["Parsed Timestamp"] = pd.to_datetime(
            df["Timestamp"],
            format="%d/%b/%Y:%H:%M:%S %z",
            errors="coerce"
        )

        hourly_attacks = df[df["Flag"]].copy()
        hourly_attacks = hourly_attacks.dropna(
            subset=["Parsed Timestamp"]
        )

        if not hourly_attacks.empty:
            hourly_attacks["Hour"] = (
                hourly_attacks["Parsed Timestamp"].dt.strftime("%H:00")
            )

            attacks_by_hour = (
                hourly_attacks.groupby("Hour")
                .size()
                .reset_index(name="Attacks")
            )
            
            st.line_chart(
                attacks_by_hour.set_index("Hour")["Attacks"]
            )

        else:
            st.info("No flagged requests with valid timestamps were found.")
        st.subheader("📋 Filter Log Records")

        selected_status = st.selectbox(
            "Filter by HTTP status",
            [
                "All",
                "Successful (2xx)",
                "Redirect (3xx)",
                "Client error (4xx)",
                "Server error (5xx)"
            ]
        )

        filtered_df = df.copy()

        if selected_status == "Successful (2xx)":
            filtered_df = df[df["Status Code"].between(200, 299)]
        elif selected_status == "Redirect (3xx)":
            filtered_df = df[df["Status Code"].between(300, 399)]
        elif selected_status == "Client error (4xx)":
            filtered_df = df[df["Status Code"].between(400, 499)]
        elif selected_status == "Server error (5xx)":
            filtered_df = df[df["Status Code"].between(500, 599)]

        st.dataframe(filtered_df, use_container_width=True)

        st.download_button(
            "⬇️ Download Analysis as CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="loglens_analysis.csv",
            mime="text/csv"
        ) 

        st.caption(
            "Flagged requests are indicators for review, not proof of an attack."
        )

else:
    st.info(
        "Upload a sample Apache/Nginx access log to see the analysis."
    )

