"""
core/logger.py — Sistema de Telemetria e Logs.
"""

import logging
import sys
from pathlib import Path


def setup_logger(
    name: str = "ctflab",
    log_file: str = "logs/ctflab.log",
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # garante que a pasta de logs existe antes de criar o arquivo
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"[fail] Não foi possível criar o arquivo de log: {e}")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        logging.Formatter("[%(levelname)s] %(message)s")
    )
    console_handler.setLevel(logging.INFO)  # Visível no terminal
    logger.addHandler(console_handler)

    return logger


logger = setup_logger()
