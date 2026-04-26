package com.example;

import org.springframework.stereotype.Component;

/**
 * Vulnerable @Component — has the POJO setters that Spring data
 * binding would walk via PropertyAccessor (CVE-2022-22965 surface).
 * BUT no @Controller / @RestController in this project @Autowireds
 * this bean or accepts it via @ModelAttribute.  Without an HTTP
 * binding path the attack cannot fire.
 */
@Component
public class OrphanBindingBean {
    private String name;
    private String secret;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
}
