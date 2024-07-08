package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NormalUserOpenApisController {

    @GetMapping("/my-third-open-api")
    public String myFirstOpenApi() {
        return "Normal User Open API";
    }

    @GetMapping("/my-forth-open-api")
    public String mySecondOpenApi() {
        return "Normal User Open API";
    }
}
