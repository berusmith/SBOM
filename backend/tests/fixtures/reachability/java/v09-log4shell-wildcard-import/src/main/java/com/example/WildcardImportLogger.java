package com.example;

import org.apache.logging.log4j.*;

/**
 * Wildcard import — `LogManager` and `Logger` are unqualified
 * references that the analyzer must resolve via the * import.
 */
public class WildcardImportLogger {
    private static final Logger logger = LogManager.getLogger(WildcardImportLogger.class);

    public void track(String userInput) {
        // Same Log4Shell — only the import shape differs.
        logger.error("event: " + userInput);
    }
}
