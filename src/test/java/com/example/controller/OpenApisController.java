package com.example.controller;

import net.coder966.spring.multisecurityrealms.annotation.AnonymousAccess;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenApisController {

    @AnonymousAccess
    @GetMapping("/my-first-open-api")
    public String myFirstOpenApi() {
        return "my-first-open-api";
    }

    @AnonymousAccess
    @GetMapping("/my-second-open-api")
    public String mySecondOpenApi() {
        return "my-second-open-api";
    }

}
