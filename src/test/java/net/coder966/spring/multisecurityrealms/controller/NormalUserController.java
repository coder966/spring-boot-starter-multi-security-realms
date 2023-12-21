package net.coder966.spring.multisecurityrealms.controller;

import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@PreAuthorize("hasRole('NORMAL_USER')")
@RestController
public class NormalUserController {

    @GetMapping("/normal-user/my-name")
    public String myName(@AuthenticationPrincipal NormalUser normalUser) {
        return normalUser.getName();
    }
}
