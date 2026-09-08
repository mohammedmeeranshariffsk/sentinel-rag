from sentinel.extraction.models import ExtractionResult
from sentinel.threat_intel.models import (
    ThreatKnowledge,
    ThreatMatch,
)


class ThreatMatcher:
    """
    Matches observable APK evidence against structured
    threat knowledge.

    Matches are investigation priorities, not malware verdicts.
    """

    def match(
        self,
        extraction: ExtractionResult,
        knowledge: list[ThreatKnowledge],
    ) -> list[ThreatMatch]:

        apk_apis = {
            api.api_name.lower()
            for api in extraction.apis
        }

        apk_permissions = {
            permission.permission.lower()
            for permission in extraction.permissions
        }

        apk_strings = {
            item.value.lower()
            for item in extraction.strings
        }

        apk_methods = {
            method.name.lower()
            for method in extraction.methods
        }

        matches: list[ThreatMatch] = []

        for record in knowledge:
            matched_apis = [
                api
                for api in record.apis
                if api.lower() in apk_apis
            ]

            matched_permissions = [
                permission
                for permission in record.permissions
                if permission.lower() in apk_permissions
            ]

            matched_strings = [
                value
                for value in record.strings
                if value.lower() in apk_strings
            ]

            matched_methods = [
                method
                for method in record.method_patterns
                if method.lower() in apk_methods
            ]

            score = (
                len(matched_apis) * 2.0
                + len(matched_permissions)
                + len(matched_strings) * 1.5
                + len(matched_methods) * 1.5
            )

            if score == 0:
                continue

            matches.append(
                ThreatMatch(
                    knowledge_id=record.knowledge_id,
                    knowledge_name=record.name,
                    score=score,
                    matched_apis=matched_apis,
                    matched_permissions=matched_permissions,
                    matched_strings=matched_strings,
                    matched_methods=matched_methods,
                )
            )

        return sorted(
            matches,
            key=lambda item: item.score,
            reverse=True,
        )