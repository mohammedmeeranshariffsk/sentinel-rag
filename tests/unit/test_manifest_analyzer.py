from pathlib import Path

import pytest

from sentinel.manifest.analyzer import ManifestAnalyzer


def write_manifest(
    path: Path,
    content: str,
) -> None:
    path.write_text(
        content,
        encoding="utf-8",
    )


def test_manifest_is_parsed(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "AndroidManifest.xml"

    write_manifest(
        manifest,
        """\
<manifest
    xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">

    <uses-permission
        android:name="android.permission.INTERNET" />

    <uses-sdk
        android:minSdkVersion="24"
        android:targetSdkVersion="35" />

    <application
        android:debuggable="true"
        android:allowBackup="true">

        <activity
            android:name=".MainActivity"
            android:exported="true">

            <intent-filter>
                <action
                    android:name="android.intent.action.VIEW" />

                <category
                    android:name="android.intent.category.BROWSABLE" />

                <data
                    android:scheme="example"
                    android:host="test" />
            </intent-filter>

        </activity>

    </application>

</manifest>
""",
    )

    result = ManifestAnalyzer().analyze(manifest)

    assert result.package_name == "com.example.test"
    assert result.min_sdk == 24
    assert result.target_sdk == 35

    assert result.debuggable is True
    assert result.allow_backup is True

    assert "android.permission.INTERNET" in result.permissions

    assert len(result.activities) == 1
    assert result.activities[0].name == ".MainActivity"
    assert result.activities[0].declared_exported is True
    assert result.activities[0].has_intent_filters is True

    assert len(result.exported_activities) == 1

    assert result.deep_links == [
        {
            "component": ".MainActivity",
            "type": "activity",
            "scheme": "example",
            "host": "test",
        }
    ]


def test_missing_manifest(
    tmp_path: Path,
) -> None:
    analyzer = ManifestAnalyzer()

    with pytest.raises(FileNotFoundError):
        analyzer.analyze(
            tmp_path / "missing.xml"
        )


def test_invalid_manifest(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "AndroidManifest.xml"

    manifest.write_text(
        "<manifest>",
        encoding="utf-8",
    )

    analyzer = ManifestAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze(manifest)


def test_exported_can_be_unknown(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "AndroidManifest.xml"

    write_manifest(
        manifest,
        """\
<manifest
    xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">

    <application>

        <activity
            android:name=".MainActivity" />

    </application>

</manifest>
""",
    )

    result = ManifestAnalyzer().analyze(manifest)

    assert result.activities[0].declared_exported is None
    assert result.activities[0].has_intent_filters is False

def test_exported_status_is_not_inferred_from_intent_filter(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "AndroidManifest.xml"

    write_manifest(
        manifest,
        """\
<manifest
    xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">

    <application>

        <activity
            android:name=".DeepLinkActivity">

            <intent-filter>

                <action
                    android:name="android.intent.action.VIEW" />

                <category
                    android:name="android.intent.category.DEFAULT" />

                <data
                    android:scheme="example"
                    android:host="test" />

            </intent-filter>

        </activity>

    </application>

</manifest>
""",
    )

    result = ManifestAnalyzer().analyze(manifest)

    component = result.activities[0]

    assert component.declared_exported is None
    assert component.has_intent_filters is True
    assert len(result.exported_activities) == 0