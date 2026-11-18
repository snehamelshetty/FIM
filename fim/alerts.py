"""
alerts.py - real-time alerts.

An alert is raised the moment the scanner records a new event. It is:
  * written to the activity log with a level matching the severity
    (the logger also prints it on the console, so you see it live), and
  * passed to any extra listener functions (callbacks).
The dashboard reads the same events from the database and shows them in the
"Security Alerts" tab.
"""
import logging

from fim.logging_setup import get_logger

logger = get_logger("alerts")

SEVERITY_LEVEL = {
    "CRITICAL": logging.CRITICAL,
    "HIGH": logging.ERROR,
    "MEDIUM": logging.WARNING,
    "LOW": logging.INFO,
}


def format_alert(event: dict) -> str:
    text = f"ALERT [{event['severity']}] {event['event_type']}: {event['path']}"
    if event.get("old_path"):
        text = f"ALERT [{event['severity']}] {event['event_type']}: {event['old_path']} -> {event['path']}"
    if event.get("details"):
        text += f"  ({event['details']})"
    return text


def raise_alert(event: dict, callbacks=None) -> None:
    """Log the alert, print a coloured banner, and call any extra listeners."""
    message = format_alert(event)
    logger.log(SEVERITY_LEVEL.get(event["severity"], logging.WARNING), message)
    for callback in callbacks or []:
        try:
            callback(event)
        except Exception:  # an alert listener must never crash the scanner
            logger.exception("Alert callback failed")
