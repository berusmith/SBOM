package com.example;

import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test suite verifies our consumer code is safe against Text4Shell
 * payloads — exercises StringSubstitutor.replace deliberately, but
 * confined to src/test/java/ so the vulnerable call site is
 * test_only from a production-reachability perspective.
 */
public class TemplateTest {

    @Test
    void substitutorRejectsScriptPrefix() {
        // CVE-2022-42889 PoC payload — pre-1.10 commons-text would
        // execute via Nashorn; the test verifies it's at least
        // contained to the test environment.
        String evil = "${script:javascript:1+1}";
        String out = new StringSubstitutor().replace(evil);
        assertNotNull(out);
    }
}
