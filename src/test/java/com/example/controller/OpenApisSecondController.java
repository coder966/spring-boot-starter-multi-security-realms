package com.example.controller;

import net.coder966.spring.multisecurityrealms.annotation.AnonymousAccess;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/open-apis")
@RestController
public class OpenApisSecondController {

    @AnonymousAccess
    @GetMapping("/my-second-open-api")
    public String mySecondOpenApi() {
        return "my-second-open-api";
    }

    @AnonymousAccess
    @GetMapping
    public String mySecondOpenApiV2() {
        return "my-second-open-api-v2";
    }

}
