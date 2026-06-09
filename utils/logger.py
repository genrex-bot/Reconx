"""ReconX - Logger setup"""

import logging
import os
from datetime import datetime


def setup_logger(verbose=False, log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"reconx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger("reconx")
    logger.setLevel(level)

    # File handler (always verbose)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    # Console handler (respects verbose flag)
    if verbose:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(ch)

    return logger
