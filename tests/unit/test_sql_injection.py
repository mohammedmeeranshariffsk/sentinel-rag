from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.rules.sql_injection import SQLInjectionRule


def make_context(tmp_path: Path) -> APKContext:
    source_path = tmp_path / "sources"
    source_path.mkdir()

    return APKContext(
        apk_path=tmp_path / "sample.apk",
        sha256="a" * 64,
        file_size=100,
        workspace=tmp_path / "workspace",
        source_path=source_path,
    )


def test_detects_sql_injection(tmp_path: Path) -> None:
    context = make_context(tmp_path)

    source_file = (
        context.source_path
        / "LoginActivity.java"
    )

    source_file.write_text(
        """
String username =
    usernameEditText.getText().toString();

String query =
    "SELECT * FROM users WHERE username='"
    + username
    + "'";

SQLiteDatabase db = getDatabase();
db.rawQuery(query, null);
""",
        encoding="utf-8",
    )

    rule = SQLInjectionRule()

    candidates = rule.analyze_file(
        source_file,
        context,
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.rule_id == "SQLI-001"
    assert candidate.vulnerability == "SQL Injection"
    assert candidate.severity == "HIGH"
    assert candidate.source == "usernameEditText.getText().toString()"
    assert candidate.sink == "SQLiteDatabase.rawQuery()"


def test_does_not_flag_constant_query(
    tmp_path: Path,
) -> None:
    context = make_context(tmp_path)

    source_file = (
        context.source_path
        / "SafeActivity.java"
    )

    source_file.write_text(
        """
String query =
    "SELECT * FROM users";

SQLiteDatabase db = getDatabase();
db.rawQuery(query, null);
""",
        encoding="utf-8",
    )

    rule = SQLInjectionRule()

    candidates = rule.analyze_file(
        source_file,
        context,
    )

    assert candidates == []

def test_detects_stringbuilder_sql_injection(
    tmp_path: Path,
) -> None:
    context = make_context(tmp_path)

    source_file = (
        context.source_path
        / "SQLinjectionActivity.java"
    )

    source_file.write_text(
        """
final EditText username =
    findViewById(R.id.userName);

StringBuilder sb =
    new StringBuilder();

sb.append(
    "SELECT * FROM users WHERE username='"
);

EditText username2 = username;

sb.append(
    username2.getText().toString()
);

sb.append("'");

String qry = sb.toString();

SQLiteDatabase db = getDatabase();

Cursor result =
    db.rawQuery(qry, null);
""",
        encoding="utf-8",
    )

    rule = SQLInjectionRule()

    candidates = rule.analyze_file(
        source_file,
        context,
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.rule_id == "SQLI-001"
    assert candidate.vulnerability == "SQL Injection"
    assert candidate.severity == "HIGH"
    assert candidate.source == "username2.getText().toString()"
    assert candidate.sink == "SQLiteDatabase.rawQuery()"