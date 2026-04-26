package com.example;

/**
 * Pure JDK arithmetic — no log4j import, no Logger instance, no
 * Log4Shell attack surface.  log4j-core is on the classpath via
 * pom.xml (perhaps a transitive pull) but our code never touches it.
 */
public class PlainCalculator {

    public int add(int a, int b) {
        return a + b;
    }

    public int multiply(int a, int b) {
        return a * b;
    }
}
