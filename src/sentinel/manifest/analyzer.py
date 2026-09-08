from dataclasses import dataclass, field
from pathlib import Path
import xml.etree.ElementTree as ET


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def android_attr(name: str) -> str:
    """Return the fully-qualified Android XML attribute name."""
    return f"{{{ANDROID_NS}}}{name}"


@dataclass
class IntentFilterInfo:
    """Represents an Android intent-filter."""

    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data_schemes: list[str] = field(default_factory=list)
    data_hosts: list[str] = field(default_factory=list)


@dataclass
class ComponentInfo:
    """Represents an Android application component."""

    name: str
    component_type: str

    declared_exported: bool | None = None
    permission: str | None = None

    intent_filters: list[IntentFilterInfo] = field(
        default_factory=list
    )

    @property
    def has_intent_filters(self) -> bool:
        """Return whether the component declares any intent filters."""
        return bool(self.intent_filters)


@dataclass
class ManifestAnalysis:
    """Structured representation of AndroidManifest.xml."""

    manifest_path: Path

    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None

    min_sdk: int | None = None
    target_sdk: int | None = None

    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext_traffic: bool | None = None

    network_security_config: str | None = None

    permissions: list[str] = field(
        default_factory=list
    )

    activities: list[ComponentInfo] = field(
        default_factory=list
    )

    services: list[ComponentInfo] = field(
        default_factory=list
    )

    receivers: list[ComponentInfo] = field(
        default_factory=list
    )

    providers: list[ComponentInfo] = field(
        default_factory=list
    )

    errors: list[str] = field(
        default_factory=list
    )

    @property
    def exported_activities(self) -> list[ComponentInfo]:
        return [
            component
            for component in self.activities
            if component.declared_exported is True
        ]

    @property
    def exported_services(self) -> list[ComponentInfo]:
        return [
            component
            for component in self.services
            if component.declared_exported is True
        ]

    @property
    def exported_receivers(self) -> list[ComponentInfo]:
        return [
            component
            for component in self.receivers
            if component.declared_exported is True
        ]

    @property
    def exported_providers(self) -> list[ComponentInfo]:
        return [
            component
            for component in self.providers
            if component.declared_exported is True
        ]

    @property
    def deep_links(self) -> list[dict[str, str]]:
        """Extract simple URI deep-link definitions."""

        links: list[dict[str, str]] = []

        for component in (
            self.activities
            + self.services
            + self.receivers
            + self.providers
        ):
            for intent_filter in component.intent_filters:
                for scheme in intent_filter.data_schemes:
                    hosts = intent_filter.data_hosts or [""]
                    for host in hosts:
                        links.append(
                            {
                                "component": component.name,
                                "type": component.component_type,
                                "scheme": scheme,
                                "host": host,
                            }
                        )

        return links


class ManifestAnalyzer:
    """Parse an AndroidManifest.xml into structured security metadata."""

    def analyze(
        self,
        manifest_path: Path | str,
    ) -> ManifestAnalysis:
        manifest_path = Path(manifest_path)

        if not manifest_path.exists():
            raise FileNotFoundError(
                f"Manifest not found: {manifest_path}"
            )

        if not manifest_path.is_file():
            raise ValueError(
                f"Manifest path is not a file: {manifest_path}"
            )

        try:
            root = ET.parse(manifest_path).getroot()
        except ET.ParseError as exc:
            raise ValueError(
                f"Invalid AndroidManifest.xml: {exc}"
            ) from exc

        analysis = ManifestAnalysis(
            manifest_path=manifest_path
        )

        self._parse_manifest_attributes(
            root,
            analysis,
        )

        self._parse_permissions(
            root,
            analysis,
        )

        application = root.find("application")

        if application is None:
            analysis.errors.append(
                "No <application> element found."
            )
            return analysis

        self._parse_application(
            application,
            analysis,
        )

        return analysis

    def _parse_manifest_attributes(
        self,
        root: ET.Element,
        analysis: ManifestAnalysis,
    ) -> None:
        """Parse package/version/sdk-related attributes."""

        analysis.package_name = root.get("package")

        analysis.version_name = root.get(
            android_attr("versionName")
        )

        analysis.version_code = root.get(
            android_attr("versionCode")
        )

        uses_sdk = root.find("uses-sdk")

        if uses_sdk is not None:
            analysis.min_sdk = self._parse_int(
                uses_sdk.get(android_attr("minSdkVersion"))
            )

            analysis.target_sdk = self._parse_int(
                uses_sdk.get(android_attr("targetSdkVersion"))
            )

    def _parse_permissions(
        self,
        root: ET.Element,
        analysis: ManifestAnalysis,
    ) -> None:
        """Parse requested Android permissions."""

        for permission in root.findall("uses-permission"):
            name = permission.get(
                android_attr("name")
            )

            if name:
                analysis.permissions.append(name)

    def _parse_application(
        self,
        application: ET.Element,
        analysis: ManifestAnalysis,
    ) -> None:
        """Parse application-level security attributes."""

        analysis.debuggable = self._parse_bool(
            application.get(android_attr("debuggable")),
            default=False,
        )

        analysis.allow_backup = self._parse_bool(
            application.get(android_attr("allowBackup")),
            default=False,
        )

        cleartext = application.get(
            android_attr("usesCleartextTraffic")
        )

        if cleartext is not None:
            analysis.uses_cleartext_traffic = self._parse_bool(
                cleartext
            )

        analysis.network_security_config = application.get(
            android_attr("networkSecurityConfig")
        )

        self._parse_components(
            application,
            "activity",
            analysis.activities,
        )

        self._parse_components(
            application,
            "activity-alias",
            analysis.activities,
        )

        self._parse_components(
            application,
            "service",
            analysis.services,
        )

        self._parse_components(
            application,
            "receiver",
            analysis.receivers,
        )

        self._parse_components(
            application,
            "provider",
            analysis.providers,
        )

    def _parse_components(
        self,
        application: ET.Element,
        tag_name: str,
        destination: list[ComponentInfo],
    ) -> None:
        """Parse components of a particular type."""

        for component in application.findall(tag_name):
            name = component.get(
                android_attr("name")
            )

            if not name:
                continue

            component_type = (
                "activity"
                if tag_name == "activity-alias"
                else tag_name
            )

            exported_attr = component.get(
                android_attr("exported")
            )

            exported: bool | None

            if exported_attr is None:
                exported = None
            else:
                exported = self._parse_bool(
                    exported_attr
                )

            permission = component.get(
                android_attr("permission")
            )

            info = ComponentInfo(
                name=name,
                component_type=component_type,
                declared_exported=exported,
                permission=permission,
                intent_filters=self._parse_intent_filters(
                    component
                ),
            )

            destination.append(info)

    def _parse_intent_filters(
        self,
        component: ET.Element,
    ) -> list[IntentFilterInfo]:
        """Parse intent filters belonging to a component."""

        filters: list[IntentFilterInfo] = []

        for element in component.findall("intent-filter"):
            info = IntentFilterInfo()

            for action in element.findall("action"):
                name = action.get(
                    android_attr("name")
                )

                if name:
                    info.actions.append(name)

            for category in element.findall("category"):
                name = category.get(
                    android_attr("name")
                )

                if name:
                    info.categories.append(name)

            for data in element.findall("data"):
                scheme = data.get(
                    android_attr("scheme")
                )

                host = data.get(
                    android_attr("host")
                )

                if scheme and scheme not in info.data_schemes:
                    info.data_schemes.append(scheme)

                if host and host not in info.data_hosts:
                    info.data_hosts.append(host)

            filters.append(info)

        return filters

    @staticmethod
    def _parse_bool(
        value: str | None,
        default: bool = False,
    ) -> bool:
        if value is None:
            return default

        return value.lower() == "true"

    @staticmethod
    def _parse_int(
        value: str | None,
    ) -> int | None:
        if value is None:
            return None

        try:
            return int(value)
        except ValueError:
            return None