package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Plain service class — no framework wiring.  Logs user input directly,
 * which is the CVE-2021-44228 trigger when log4j-core is pre-2.15.
 */
public class UserService {
    private static final Logger logger = LogManager.getLogger(UserService.class);

    public void handleSignup(String username, String email) {
        // userInput flows into the message string — pre-2.15 log4j evaluates
        // ${jndi:...} lookups inside, achieving RCE.
        logger.error("New signup: " + username + " <" + email + ">");
    }
}
