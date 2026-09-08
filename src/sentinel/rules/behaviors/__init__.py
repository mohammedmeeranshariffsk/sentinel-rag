from sentinel.rules.behaviors.accessibility_abuse import (
    AccessibilityAbuseRule,
)
from sentinel.rules.behaviors.base import BehaviorRule


def get_default_behavior_rules() -> list[BehaviorRule]:
    return [
        AccessibilityAbuseRule(),
    ]