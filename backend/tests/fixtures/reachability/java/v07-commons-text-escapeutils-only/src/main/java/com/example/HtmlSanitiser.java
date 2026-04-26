package com.example;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.text.WordUtils;

/**
 * Uses commons-text for HTML escaping and capitalisation only —
 * never instantiates StringSubstitutor, so the prefix-evaluation
 * attack surface (CVE-2022-42889) doesn't exist here.
 */
public class HtmlSanitiser {

    public String safeEscape(String html) {
        return StringEscapeUtils.escapeHtml4(html);
    }

    public String prettyName(String raw) {
        return WordUtils.capitalize(raw);
    }
}
