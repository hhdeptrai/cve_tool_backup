from src.database import DatabaseManager
import os
from dotenv import load_dotenv

load_dotenv()

def reset_database():
    db = DatabaseManager()
    conn = db.get_connection()
    cursor = conn.cursor()
    print("Dropping old table `web_cve_census_master`...")
    cursor.execute("DROP TABLE IF EXISTS web_cve_census_master;")
    conn.commit()
    db.return_connection(conn)
    print("Table dropped successfully! The collector will recreate it.")

if __name__ == "__main__":
    reset_database()
