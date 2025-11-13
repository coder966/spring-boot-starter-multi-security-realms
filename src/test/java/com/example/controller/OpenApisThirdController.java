package com.example.controller;

import net.coder966.spring.multisecurityrealms.annotation.AnonymousAccess;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@PreAuthorize("permitRealm('ADMIN_USER')")
@RequestMapping("/open-apis-3")
@RestController
public class OpenApisThirdController {

    @AnonymousAccess
    @GetMapping("/my-third-open-api")
    public String myThirdOpenApi() {
        return "my-third-open-api";
    }

}
