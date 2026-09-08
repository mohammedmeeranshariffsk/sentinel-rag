from sentinel.rules.sql_injection import SQLInjectionRule


def get_default_rules() -> list[SQLInjectionRule]:
    """Return the security rules enabled for the prototype."""

    return [
        SQLInjectionRule(),
    ]