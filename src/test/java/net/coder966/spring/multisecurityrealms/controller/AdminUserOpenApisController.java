package net.coder966.spring.multisecurityrealms.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminUserOpenApisController {

    @GetMapping("/my-first-open-api")
    public String myFirstOpenApi() {
        return "Admin User Open API";
    }

    @GetMapping("/my-second-open-api")
    public String mySecondOpenApi() {
        return "Admin User Open API";
    }
}
