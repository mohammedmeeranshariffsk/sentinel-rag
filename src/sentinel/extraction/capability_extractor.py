from sentinel.extraction.models import (
    ExtractedAPI,
    ExtractedPermission,
    ExtractedString,
    SecurityCapability,
)


class CapabilityExtractor:
    """
    Maps observable APK evidence to generic security capabilities.

    A capability is not equivalent to malicious behavior.
    """

    API_CAPABILITIES = {
        "DexClassLoader": (
            "CAP-DYNAMIC-LOAD",
            "Dynamic Code Loading",
            "execution",
        ),
        "PathClassLoader": (
            "CAP-DYNAMIC-LOAD",
            "Dynamic Code Loading",
            "execution",
        ),
        "getRootInActiveWindow": (
            "CAP-ACCESSIBILITY",
            "Accessibility Interaction",
            "accessibility",
        ),
        "performGlobalAction": (
            "CAP-ACCESSIBILITY",
            "Accessibility Interaction",
            "accessibility",
        ),
        "dispatchGesture": (
            "CAP-ACCESSIBILITY",
            "Accessibility Interaction",
            "accessibility",
        ),
        "exec": (
            "CAP-PROCESS-EXEC",
            "Process Execution",
            "execution",
        ),
        "start": (
            "CAP-PROCESS-EXEC",
            "Process Execution",
            "execution",
        ),
        "loadLibrary": (
            "CAP-NATIVE",
            "Native Code Loading",
            "native",
        ),
        "load": (
            "CAP-NATIVE",
            "Native Code Loading",
            "native",
        ),
    }

    PERMISSION_CAPABILITIES = {
        "android.permission.RECEIVE_BOOT_COMPLETED": (
            "CAP-PERSISTENCE",
            "Boot Persistence",
            "persistence",
        ),
        "android.permission.REQUEST_INSTALL_PACKAGES": (
            "CAP-PACKAGE-INSTALL",
            "Package Installation",
            "installation",
        ),
        "android.permission.SYSTEM_ALERT_WINDOW": (
            "CAP-OVERLAY",
            "Overlay Capability",
            "ui",
        ),
    }

    def extract(
        self,
        apis: list[ExtractedAPI],
        strings: list[ExtractedString],
        permissions: list[ExtractedPermission],
    ) -> list[SecurityCapability]:
        matches: dict[str, SecurityCapability] = {}

        for api in apis:
            mapping = self.API_CAPABILITIES.get(
                api.api_name
            )

            if mapping is None:
                continue

            capability_id, name, category = mapping

            capability = matches.setdefault(
                capability_id,
                SecurityCapability(
                    capability_id=capability_id,
                    name=name,
                    category=category,
                    confidence=1.0,
                ),
            )

            indicator = api.full_reference

            if indicator not in capability.matched_indicators:
                capability.matched_indicators.append(
                    indicator
                )

            evidence_ref = (
                f"{api.location.file}:"
                f"{api.location.line}"
            )

            if evidence_ref not in capability.evidence_refs:
                capability.evidence_refs.append(
                    evidence_ref
                )

        for permission in permissions:
            mapping = self.PERMISSION_CAPABILITIES.get(
                permission.permission
            )

            if mapping is None:
                continue

            capability_id, name, category = mapping

            capability = matches.setdefault(
                capability_id,
                SecurityCapability(
                    capability_id=capability_id,
                    name=name,
                    category=category,
                    confidence=1.0,
                ),
            )

            if (
                permission.permission
                not in capability.matched_indicators
            ):
                capability.matched_indicators.append(
                    permission.permission
                )

        return list(matches.values())