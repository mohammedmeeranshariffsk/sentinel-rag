from sentinel.extraction.capability_extractor import (
    CapabilityExtractor,
)
from sentinel.extraction.models import (
    EvidenceLocation,
    ExtractedAPI,
    ExtractedPermission,
)


def test_extract_security_capabilities():
    apis = [
        ExtractedAPI(
            api_name="getRootInActiveWindow",
            full_reference="service.getRootInActiveWindow",
            location=EvidenceLocation(
                file="Example.java",
                line=10,
            ),
        ),
        ExtractedAPI(
            api_name="DexClassLoader",
            full_reference="dalvik.system.DexClassLoader",
            location=EvidenceLocation(
                file="Loader.java",
                line=20,
            ),
        ),
    ]

    permissions = [
        ExtractedPermission(
            permission="android.permission.RECEIVE_BOOT_COMPLETED"
        )
    ]

    capabilities = CapabilityExtractor().extract(
        apis=apis,
        strings=[],
        permissions=permissions,
    )

    ids = {
        capability.capability_id
        for capability in capabilities
    }

    assert "CAP-ACCESSIBILITY" in ids
    assert "CAP-DYNAMIC-LOAD" in ids
    assert "CAP-PERSISTENCE" in ids