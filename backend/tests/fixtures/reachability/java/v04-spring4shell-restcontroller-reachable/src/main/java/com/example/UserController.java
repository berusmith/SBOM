package com.example;

import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @RestController + @PostMapping + @ModelAttribute UserDto = the
 * Spring4Shell trigger pattern.  Spring binds request parameters
 * into the UserDto via reflective property access, including the
 * `class.module.classLoader.*` chain that allows attacker writes.
 */
@RestController
public class UserController {

    @PostMapping("/users")
    public String createUser(@ModelAttribute UserDto dto) {
        // The bind itself is the attack surface — by the time we
        // reach here, the malicious property writes have already
        // happened during framework data binding.
        return "created: " + dto.getName();
    }
}
