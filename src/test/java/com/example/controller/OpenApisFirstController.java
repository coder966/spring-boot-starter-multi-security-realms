package com.example.controller;

import net.coder966.spring.multisecurityrealms.annotation.AnonymousAccess;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenApisFirstController {

    @GetMapping("/my-first-open-api")
    @AnonymousAccess
    public String myFirstOpenApi() {
        return "my-first-open-api";
    }

}
