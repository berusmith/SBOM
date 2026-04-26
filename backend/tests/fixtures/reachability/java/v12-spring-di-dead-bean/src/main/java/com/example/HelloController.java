package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The only HTTP entry point — takes a String query param, returns
 * a String.  Crucially, it does NOT @Autowired OrphanBindingBean
 * and does NOT take any @ModelAttribute parameters.  No path from
 * HTTP request to the vulnerable POJO data binding exists.
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        return "hello " + name;
    }
}
