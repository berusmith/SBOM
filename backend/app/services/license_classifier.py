"""License risk classifier: categorizes SPDX licenses into Permissive / Copyleft / Commercial."""

# Permissive licenses (low risk for proprietary software)
PERMISSIVE = {
    "MIT", "Apache-2.0", "Apache-2.0-only", "Apache-2.0-or-later",
    "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
    "ISC", "Unlicense", "0BSD",
    "Zlib", "BSL-1.0",  # Boost Software License
    "CC0-1.0",  # Public Domain
}

# Copyleft licenses (medium-high risk: require reciprocal licensing)
COPYLEFT = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-2.0+",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "GPL-3.0+",
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.0+",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-2.1+",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-3.0+",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-3.0+",
    "MPL-2.0",  # Mozilla Public License
    "EPL-1.0", "EPL-2.0",  # Eclipse Public License
    "GFDL-1.1", "GFDL-1.2", "GFDL-1.3",  # GNU Free Documentation License
    "OFL-1.1",  # SIL Open Font License (weak copyleft for fonts)
}

# Commercial/Proprietary licenses (requires special legal review)
COMMERCIAL = {
    "BUSL-1.1",  # Business Source License
    "Elastic-2.0",  # Elastic License
    "SSPL-1.0",  # Server Side Public License
    "Commons-Clause",  # Commons Clause
}


def classify_license(license_str: str) -> str:
    """
    Classify a SPDX license identifier into risk category.

    Args:
        license_str: SPDX license identifier or expression (e.g., "MIT", "GPL-3.0-or-later", "Apache-2.0 OR MIT")

    Returns:
        "permissive", "copyleft", "commercial", or "unknown"
    """
    if not license_str or not license_str.strip():
        return "unknown"

    license_str = license_str.strip()

    # Handle expressions: "A OR B" → if any is copyleft, return copyleft; if any is commercial, return commercial
    # This is a simplified approach; proper SPDX license expression parsing would be more complex
    terms = license_str.replace(" AND ", " OR ").split(" OR ")

    categories = set()
    for term in terms:
        term = term.strip()

        # Exact match (case-insensitive)
        if term.upper() in COMMERCIAL:
            categories.add("commercial")
        elif term.upper() in COPYLEFT:
            categories.add("copyleft")
        elif term.upper() in PERMISSIVE:
            categories.add("permissive")
        else:
            # Fuzzy match: check if any known license is a substring
            term_lower = term.lower()
            for commercial_lic in COMMERCIAL:
                if commercial_lic.lower() in term_lower:
                    categories.add("commercial")
                    break
            else:
                for copyleft_lic in COPYLEFT:
                    if copyleft_lic.lower() in term_lower:
                        categories.add("copyleft")
                        break
                else:
                    for permissive_lic in PERMISSIVE:
                        if permissive_lic.lower() in term_lower:
                            categories.add("permissive")
                            break

    if not categories:
        return "unknown"

    # Priority: commercial > copyleft > permissive
    if "commercial" in categories:
        return "commercial"
    if "copyleft" in categories:
        return "copyleft"
    if "permissive" in categories:
        return "permissive"

    return "unknown"
