import os

import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))


_connection_pool = None


def _build_db_config():
    return {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "port": int(os.getenv("MYSQL_PORT", 3306)),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DB", "securescan"),
        "autocommit": True,
    }


def _get_pool():
    global _connection_pool
    if _connection_pool is None:
        try:
            _connection_pool = pooling.MySQLConnectionPool(
                pool_name="securescan_pool",
                pool_size=5,
                **_build_db_config(),
            )
        except mysql.connector.Error as e:
            raise RuntimeError(
                "MySQL connection pool initialization failed. "
                "Check .env MYSQL_* settings and ensure MySQL is running. "
                f"Original error: {e}"
            )
    return _connection_pool


def get_db():
    return _get_pool().get_connection()
