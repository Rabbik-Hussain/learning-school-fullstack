import psycopg

DATABASE_URL = (
    "host=127.0.0.1 "
    "port=5432 "
    "dbname=learning_school "
    "user=postgres"
)


def get_connection():
    return psycopg.connect(DATABASE_URL)