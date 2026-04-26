package com.example;

import static org.apache.logging.log4j.LogManager.getLogger;

import org.apache.logging.log4j.Logger;

/**
 * Static import edge — `getLogger(...)` is the unqualified form of
 * `LogManager.getLogger(...)`.  Analyzer must trace the static
 * import to resolve the call back to log4j-core.
 */
public class StaticImportLogger {
    private static final Logger logger = getLogger(StaticImportLogger.class);

    public void audit(String userInput) {
        // Same Log4Shell vulnerability — the import path differs but
        // the runtime behaviour is identical.
        logger.error("audit event: " + userInput);
    }
}
