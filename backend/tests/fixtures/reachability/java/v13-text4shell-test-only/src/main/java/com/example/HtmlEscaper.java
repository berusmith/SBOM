package com.example;

import org.apache.commons.text.StringEscapeUtils;

/** Production code uses only the safe surface — StringEscapeUtils,
 *  no StringSubstitutor.  Text4Shell unreachable from main code. */
public class HtmlEscaper {

    public String escape(String html) {
        return StringEscapeUtils.escapeHtml4(html);
    }
}
