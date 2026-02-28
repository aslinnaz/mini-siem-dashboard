import pandas as pd

def brute_force_alerts(df: pd.DataFrame, threshold: int = 5) -> pd.DataFrame:
    failed = df[df["event"] == "failed_login"].copy()
    counts = failed["ip"].value_counts().reset_index()
    counts.columns = ["ip", "failed_count"]
    alerts = counts[counts["failed_count"] >= threshold].copy()
    alerts["alert"] = "BRUTE_FORCE_SUSPECT"
    return alerts.sort_values("failed_count", ascending=False)