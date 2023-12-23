package net.coder966.spring.multisecurityrealms.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NormalUserOpenApisController {

    @GetMapping("/normal-user/my-first-open-api")
    public String myFirstOpenApi() {
        return "Normal User Open API";
    }

    @GetMapping("/normal-user/my-second-open-api")
    public String mySecondOpenApi() {
        return "Normal User Open API";
    }
}
