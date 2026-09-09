from pathlib import Path
import re

from sentinel.extraction.models import ExtractionResult
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.profiles.models import (
    ExtractionProfile,
    ProfileAnalysis,
    ProfileArtifact,
    ProfileArtifactMatch,
    ProfileBehaviorAssessment,
    ProfileOutcome,
)


class ProfileAnalyzer:
    """Match profile seeds deterministically; do not infer graph edges or family."""

    ELIGIBLE_CLASSIFICATIONS = {
        "reported_exact_token",
        "reported_behavior",
        "behavior_derived_search_target",
    }

    def analyze(
        self,
        profile: ExtractionProfile,
        profile_path: Path | str,
        extraction: ExtractionResult,
        manifest: ManifestAnalysis | None,
    ) -> ProfileAnalysis:
        matches: list[tuple[ProfileArtifactMatch, ProfileArtifact]] = []
        for group_name in (
            "manifest", "api_calls", "exact_strings", "components_and_intents"
        ):
            for artifact in getattr(profile.extractors, group_name):
                match = self._match(group_name, artifact, extraction, manifest)
                if match is not None:
                    matches.append((match, artifact))

        assessments = []
        for bundle in profile.behavior_bundles:
            related = [
                match for match, artifact in matches
                if bundle.template_ref in artifact.supports
                and artifact.classification in self.ELIGIBLE_CLASSIFICATIONS
            ]
            outcome = (
                ProfileOutcome.NO_SEED if not related
                else ProfileOutcome.INDICATOR_MATCH if len(related) == 1
                else ProfileOutcome.APK_COOCCURRENCE
            )
            assessments.append(ProfileBehaviorAssessment(
                bundle_id=bundle.id,
                template_ref=bundle.template_ref,
                outcome=outcome,
                matched_evidence_refs=[item.reference for item in related],
                required_relationship=bundle.required_relationship,
                missing_evidence=[] if not related else [
                    f"Required APK-local relationship not yet verified: {bundle.required_relationship}"
                ],
            ))

        eligible_count = sum(
            artifact.classification in self.ELIGIBLE_CLASSIFICATIONS
            for _, artifact in matches
        )
        conclusion = (
            f"{eligible_count} profile seed(s) matched APK evidence. "
            "The matches prioritize behavior verification and do not establish family attribution."
            if eligible_count else
            "No source-backed or behavior-derived profile seeds matched the extracted APK evidence."
        )
        return ProfileAnalysis(
            profile_path=str(profile_path),
            profile_schema_version=profile.schema_version,
            profile_status=profile.status,
            family_id=profile.family_id,
            artifact_matches=[item for item, _ in matches],
            behavior_assessments=assessments,
            conclusion=conclusion,
            limitations=[
                "Artifact presence and APK-wide co-occurrence do not prove a behavior relationship.",
                "Structural checks and cross-method/component graph edges are not verified by this prototype.",
                "Profile content is external research context, not APK evidence.",
            ],
        )

    def _match(
        self, group: str, artifact: ProfileArtifact,
        extraction: ExtractionResult, manifest: ManifestAnalysis | None,
    ) -> ProfileArtifactMatch | None:
        location: tuple[str | None, int | None] = (None, None)
        matched = False
        if group == "manifest" and artifact.value:
            if artifact.declaration_type == "component_binding_permission":
                services = manifest.services if manifest else []
                matched = any(item.permission == artifact.value for item in services)
            else:
                matched = any(item.permission == artifact.value for item in extraction.permissions)
        elif group == "api_calls" and artifact.method:
            api = next((
                item for item in extraction.apis
                if item.api_name == artifact.method
                and self._api_owner_matches(
                    artifact, item.full_reference, item.location.file
                )
            ), None)
            if api:
                matched = True
                location = (api.location.file, api.location.line)
        elif group == "exact_strings" and artifact.value:
            if artifact.kind == "package":
                matched = bool(manifest and manifest.package_name == artifact.value)
            else:
                string = next((item for item in extraction.strings if self._string_matches(artifact, item.value)), None)
                if string:
                    matched = True
                    location = (string.location.file, string.location.line)
        elif group == "components_and_intents" and artifact.value and manifest:
            actions = [
                action
                for component in manifest.activities + manifest.services + manifest.receivers + manifest.providers
                for intent_filter in component.intent_filters
                for action in intent_filter.actions
            ]
            matched = any(
                action == artifact.value or action.rsplit(".", 1)[-1] == artifact.value
                for action in actions
            )
        if not matched:
            return None
        value = artifact.display_value
        reference = f"apk:profile:{group}:{len(value)}:{value}"
        return ProfileArtifactMatch(
            reference=reference, artifact_group=group, value=value,
            classification=artifact.classification, source_refs=artifact.source_refs,
            file=location[0], line=location[1],
        )

    @staticmethod
    def _string_matches(artifact: ProfileArtifact, value: str) -> bool:
        if artifact.kind in {"endpoint_suffix", "host_suffix"}:
            return value.endswith(artifact.value or "")
        return value == artifact.value

    @staticmethod
    def _api_owner_matches(
        artifact: ProfileArtifact,
        full_reference: str,
        source_file: str,
    ) -> bool:
        """Require the call receiver to resolve to the profile owner type."""
        if not artifact.owner or "." not in full_reference:
            return False

        expected = artifact.owner.rsplit(".", 1)[-1]
        receiver = full_reference.rsplit(".", 1)[0]

        # Static calls retain the class name in ExtractedAPI.full_reference.
        if receiver == expected:
            return True
        if receiver[:1].isupper():
            return False

        try:
            source = Path(source_file).read_text(
                encoding="utf-8", errors="ignore"
            )
        except OSError:
            return False

        declaration = re.compile(
            rf"\b(?P<type>[A-Z][A-Za-z0-9_$.]*(?:<[^;=()]+>)?)\s+"
            rf"(?:this\.)?{re.escape(receiver)}\b"
        )
        return any(
            match.group("type")
            .split("<", 1)[0]
            .rsplit(".", 1)[-1]
            == expected
            for match in declaration.finditer(source)
        )
