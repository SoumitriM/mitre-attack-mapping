"""Platform normalization utilities for CVE-to-ATT&CK mapping.

Maps CVE platform labels to standard ATT&CK platform names.
Used consistently across extraction, mapping, and validation layers.
"""


# Mapping from CVE platform labels to ATT&CK standard platforms
PLATFORM_MAPPINGS = {
    # Windows variants
    "x64-based systems": "windows",
    "32-bit systems": "windows",
    "arm64-based systems": "windows",
    "x86-based systems": "windows",
    "windows": "windows",
    "x86": "windows",
    "x64": "windows",
    "x86_64": "windows",
    "amd64": "windows",
    "ia64": "windows",
    # Linux variants
    "linux": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "centos": "linux",
    "fedora": "linux",
    "rhel": "linux",
    "gnu/linux": "linux",
    # macOS variants
    "macos": "macos",
    "mac os": "macos",
    "mac os x": "macos",
    "osx": "macos",
    # Network/cloud
    "network": "network",
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "google cloud": "gcp",
    # Mobile
    "ios": "ios",
    "iphone": "ios",
    "ipad": "ios",
    "android": "android",
    # Other
    "saas": "saas",
}


def normalize_platform(platform_label: str) -> str:
    """Normalize a CVE platform label to ATT&CK standard.

    Args:
        platform_label: Platform label from CVE

    Returns:
        Normalized platform name (lowercase, standard format)

    Examples:
        normalize_platform("x64-based Systems") -> "windows"
        normalize_platform("Linux") -> "linux"
        normalize_platform("Unknown") -> "unknown"
    """
    if not platform_label:
        return "unknown"

    normalized_input = platform_label.lower().strip()

    # Direct mapping lookup
    if normalized_input in PLATFORM_MAPPINGS:
        return PLATFORM_MAPPINGS[normalized_input]

    # Partial matching (e.g., "Windows Server 2019" -> "windows")
    for key, value in PLATFORM_MAPPINGS.items():
        if key in normalized_input:
            return value

    # If no match found, return the normalized input as-is
    return normalized_input


def normalize_platforms(platforms: list[str] | set[str]) -> set[str]:
    """Normalize a collection of platform labels.

    Args:
        platforms: Collection of platform labels

    Returns:
        Set of normalized platform names

    Examples:
        normalize_platforms(["x64-based Systems", "Windows"])
        -> {"windows"}

        normalize_platforms(["Linux", "macOS"])
        -> {"linux", "macos"}
    """
    if not platforms:
        return set()

    return {normalize_platform(p) for p in platforms}


def platforms_compatible(
    cve_platforms: list[str] | set[str],
    technique_platforms: list[str] | set[str],
) -> bool:
    """Check if CVE platforms are compatible with technique platforms.

    Returns True if:
    - Either list is empty (universal compatibility)
    - There's at least one normalized platform in common

    Args:
        cve_platforms: Platforms from CVE
        technique_platforms: Platforms from ATT&CK technique

    Returns:
        True if platforms are compatible, False otherwise

    Examples:
        platforms_compatible(["x64-based Systems"], ["windows"])
        -> True

        platforms_compatible(["Linux"], ["windows"])
        -> False
    """
    # Empty sets mean universal compatibility
    if not cve_platforms or not technique_platforms:
        return True

    # Normalize both sets
    norm_cve = normalize_platforms(cve_platforms)
    norm_technique = normalize_platforms(technique_platforms)

    # Check for intersection
    return bool(norm_cve & norm_technique)
