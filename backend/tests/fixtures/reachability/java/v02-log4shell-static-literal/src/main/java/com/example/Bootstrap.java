package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Logger.info is called, but only with compile-time string literals —
 * no user input ever flows into the message, so the JNDI lookup path
 * has nothing exploitable to expand.
 */
public class Bootstrap {
    private static final Logger logger = LogManager.getLogger(Bootstrap.class);

    public void start() {
        // Pure literals — no taint source.
        logger.info("Service starting up");
        logger.info("Configuration loaded");
    }

    public void shutdown() {
        logger.info("Service shutting down");
    }
}
