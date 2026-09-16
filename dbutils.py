import mysql.connector
import configparser
from datetime import datetime


def connect_to_db(create_schema=False):
    # Read the configuration file
    config = configparser.ConfigParser()
    config.read("config.ini")

    # Extract database connection details
    db_config = config["database"]

    # Connect to the database server (initially without specifying the database)
    db_conn = mysql.connector.connect(
        host=db_config["host"], user=db_config["user"], password=db_config["password"]
    )
    cursor = db_conn.cursor()
    try:
        # If schema creation is requested, create the database and table if they don't exist
        if create_schema:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['database']}")
            db_conn.database = db_config["database"]
            create_plugin_data_table(cursor)
            create_plugin_results_table(cursor)
        else:
            db_conn.database = db_config["database"]

    except mysql.connector.errors.ProgrammingError as e:
        if "1049" in str(e):
            raise SystemExit(
                "Database {} does not exist. Please run with the '--create-schema' flag to create the database.".format(
                    db_config["database"]
                )
            )

    return db_conn, cursor


def delete_results_table(cursor):
    cursor.execute("DROP TABLE IF EXISTS PluginResults")
    create_plugin_results_table(cursor)


def create_plugin_data_table(cursor):
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS PluginData (
        slug VARCHAR(255) PRIMARY KEY,
        version VARCHAR(255),
        active_installs INT,
        downloaded INT,
        last_updated DATETIME,
        added_date DATE,
        download_link TEXT
    )
    """
    )


def create_plugin_results_table(cursor):
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS PluginResults (
        id INT AUTO_INCREMENT PRIMARY KEY,
        slug VARCHAR(255),
        file_path VARCHAR(255),
        check_id VARCHAR(255),
        start_line INT,
        end_line INT,
        vuln_lines TEXT,
        FOREIGN KEY (slug) REFERENCES PluginData(slug)
    )
    """
    )


def insert_plugin_into_db(cursor, plugin):
    # Prepare SQL upsert statement
    sql = """
    INSERT INTO PluginData (slug, version, active_installs, downloaded, last_updated, added_date, download_link)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        version = VALUES(version),
        active_installs = VALUES(active_installs),
        downloaded = VALUES(downloaded),
        last_updated = VALUES(last_updated),
        added_date = VALUES(added_date),
        download_link = VALUES(download_link)
    """

    # Prepare data for database insertion
    last_updated = plugin.get("last_updated", None)
    added_date = plugin.get("added", None)

    # Convert date formats if available
    if last_updated:
        last_updated = datetime.strptime(last_updated, "%Y-%m-%d %I:%M%p %Z").strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    if added_date:
        added_date = datetime.strptime(added_date, "%Y-%m-%d").strftime("%Y-%m-%d")

    data = (
        plugin["slug"],
        plugin.get("version", "N/A"),
        int(plugin.get("active_installs", 0)),
        int(plugin.get("downloaded", 0)),
        last_updated,
        added_date,
        plugin.get("download_link", "N/A"),
    )

    try:
        cursor.execute(sql, data)
    except mysql.connector.errors.ProgrammingError as e:
        if "1146" in str(e):
            raise SystemExit(
                "Table does not exist. Please run with the '--create-schema' flag to create the table."
            )


def insert_result_into_db(cursor, slug, result):
    sql = (
        "INSERT INTO PluginResults (slug, file_path, check_id, start_line, end_line, vuln_lines)"
        "VALUES (%s, %s, %s, %s, %s, %s)"
    )
    data = (
        slug,
        result["path"],
        result["check_id"],
        result["start"]["line"],
        result["end"]["line"],
        result["extra"]["lines"],
    )
    try:
        cursor.execute(sql, data)

    except mysql.connector.errors.ProgrammingError as e:
        if "1146" in str(e):
            raise SystemExit(
                "Table does not exist. Please run with the '--create-schema' flag to create the table."
            )


# ---------------------------------------------------------------------------
# AI triyaj katmani icin eklenen semalar ve sorgular (fork eklentisi)
# ---------------------------------------------------------------------------

TRIAGE_COLUMNS = {
    "triage_verdict": "VARCHAR(20)",   # real | likely | false_positive
    "confidence": "FLOAT",             # 0.0 - 1.0
    "vuln_class": "VARCHAR(64)",       # or. sqli, xss_stored, csrf, lfi, idor...
    "auth_context": "VARCHAR(20)",     # unauth | subscriber | admin
    "exploitability": "VARCHAR(20)",   # easy | medium | hard
    "triage_notes": "TEXT",
    "triaged_at": "DATETIME",
}


def ensure_triage_schema(cursor):
    """PluginResults tablosuna triyaj kolonlarini idempotent sekilde ekler.
    MySQL 'ADD COLUMN IF NOT EXISTS' desteklemedigi icin information_schema'dan
    mevcut kolonlari kontrol edip eksik olanlari ekleriz."""
    cursor.execute(
        """
        SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'PluginResults'
        """
    )
    existing = {row[0] for row in cursor.fetchall()}
    for name, coltype in TRIAGE_COLUMNS.items():
        if name not in existing:
            cursor.execute(f"ALTER TABLE PluginResults ADD COLUMN {name} {coltype}")
    # Sorgulari hizlandirmak icin index
    cursor.execute(
        """
        SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'PluginResults'
          AND INDEX_NAME = 'idx_triage_verdict'
        """
    )
    if not cursor.fetchall():
        cursor.execute(
            "CREATE INDEX idx_triage_verdict ON PluginResults (triage_verdict)"
        )


def get_untriaged_results(cursor, limit=None):
    """Henuz triyaj edilmemis bulgulari, eklenti install sayisiyla birlikte doner."""
    sql = """
        SELECT r.id, r.slug, r.file_path, r.check_id, r.start_line, r.end_line,
               r.vuln_lines, d.active_installs, d.version
        FROM PluginResults r
        LEFT JOIN PluginData d ON r.slug = d.slug
        WHERE r.triage_verdict IS NULL
        ORDER BY d.active_installs DESC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    cursor.execute(sql)
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def update_triage_result(cursor, result_id, verdict, confidence, vuln_class,
                         auth_context, exploitability, notes):
    cursor.execute(
        """
        UPDATE PluginResults
        SET triage_verdict=%s, confidence=%s, vuln_class=%s, auth_context=%s,
            exploitability=%s, triage_notes=%s, triaged_at=NOW()
        WHERE id=%s
        """,
        (verdict, confidence, vuln_class, auth_context, exploitability, notes, result_id),
    )


def get_prioritized_findings(cursor, verdicts=("real", "likely"),
                             auth_contexts=("unauth", "subscriber"),
                             min_confidence=0.5, limit=100):
    """Triyaj sonrasi oncelik kuyrugu: dogrulanacak bulgular.
    Sira: auth_context (unauth once), install sayisi, guven skoru."""
    placeholders_v = ",".join(["%s"] * len(verdicts))
    placeholders_a = ",".join(["%s"] * len(auth_contexts))
    sql = f"""
        SELECT r.id, r.slug, r.file_path, r.check_id, r.start_line, r.end_line,
               r.vuln_class, r.auth_context, r.exploitability, r.confidence,
               r.triage_notes, r.vuln_lines, d.active_installs, d.version, d.download_link
        FROM PluginResults r
        LEFT JOIN PluginData d ON r.slug = d.slug
        WHERE r.triage_verdict IN ({placeholders_v})
          AND r.auth_context IN ({placeholders_a})
          AND r.confidence >= %s
        ORDER BY FIELD(r.auth_context, 'unauth', 'subscriber', 'admin'),
                 d.active_installs DESC, r.confidence DESC
        LIMIT %s
    """
    params = list(verdicts) + list(auth_contexts) + [min_confidence, int(limit)]
    cursor.execute(sql, params)
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def get_finding_by_id(cursor, result_id):
    cursor.execute(
        """
        SELECT r.id, r.slug, r.file_path, r.check_id, r.start_line, r.end_line,
               r.vuln_class, r.auth_context, r.exploitability, r.confidence,
               r.triage_notes, r.vuln_lines, d.active_installs, d.version, d.download_link
        FROM PluginResults r
        LEFT JOIN PluginData d ON r.slug = d.slug
        WHERE r.id = %s
        """,
        (result_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    cols = [c[0] for c in cursor.description]
    return dict(zip(cols, row))
