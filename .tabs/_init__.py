import pandas as pd
import sqlite3
from datetime import datetime, timedelta

# Path to SQLite database (adjust this if you're using a remote or in-memory DB)
DATABASE_PATH = "data/anomaly_predictions.db"

def load_predictions_from_sqlitecloud(type: str = "dns", time_window: str = "-24h") -> pd.DataFrame:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Determine table based on type
        table_name = "dns_predictions" if type == "dns" else "dos_predictions"

        # Convert time_window like '-24h' or '-7d' into actual datetime
        now = datetime.now()
        if time_window.endswith("h"):
            hours = int(time_window.strip("-h"))
            start_time = now - timedelta(hours=hours)
        elif time_window.endswith("d"):
            days = int(time_window.strip("-d"))
            start_time = now - timedelta(days=days)
        else:
            start_time = now - timedelta(days=1)  # default fallback to 1 day

        # Query data
        query = f"""
            SELECT * FROM {table_name}
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn, params=(start_time.strftime("%Y-%m-%d %H:%M:%S"),))
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    except Exception as e:
        print(f"Error loading predictions: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

def get_historical_dns(start_date, end_date) -> pd.DataFrame:
    return _get_data_by_date_range("dns_predictions", start_date, end_date)

def get_historical_dos(start_date, end_date) -> pd.DataFrame:
    return _get_data_by_date_range("dos_predictions", start_date, end_date)

def _get_data_by_date_range(table: str, start_date, end_date) -> pd.DataFrame:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        query = f"""
            SELECT * FROM {table}
            WHERE DATE(timestamp) BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """
        df = pd.read_sql_query(query, conn, params=(start_date, end_date))
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as e:
        print(f"Error retrieving historical data: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

