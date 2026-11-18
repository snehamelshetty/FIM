"""
logging_setup.py - activity logging with Python's built-in `logging` module.

Every important action (baseline created, file modified, alert raised, baseline
approved...) is written to  fim_data/logs/fim_activity.log  with a timestamp.
"""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fim import config

LOGGER_NAME = "fim"
_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"


def setup_logging(data_dir=None, console=True, level=logging.INFO) -> logging.Logger:
    """Configure the 'fim' logger once (safe to call many times)."""
    data_dir = Path(data_dir or config.DATA_DIR)
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    # Remove handlers from earlier calls so we never log lines twice.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    # Rotating file: when it reaches 1 MB, start a new file (keep 5 old ones).
    file_handler = RotatingFileHandler(
        log_dir / "fim_activity.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(console_handler)
    return logger


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
