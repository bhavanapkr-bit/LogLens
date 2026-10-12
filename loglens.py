import streamlit as st
import pandas as pd
from collections import Counter
import re
import json
import geoip2.database
from pathlib import Path
from parser import iter_log_records
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
        type=["log", "txt"]
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


if uploaded_file:
    records = list(iter_log_records(uploaded_file))

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

