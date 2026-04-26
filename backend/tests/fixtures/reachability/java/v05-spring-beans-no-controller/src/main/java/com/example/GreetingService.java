package com.example;

import org.springframework.stereotype.Service;

/**
 * Internal Spring service — no HTTP entrypoint exposes this.  Even if
 * an attacker could call greet(), there's no request-binding path to
 * trigger Spring4Shell's PropertyAccessor walk.
 */
@Service
public class GreetingService {
    public String greet(String who) {
        return "hello " + who;
    }
}
