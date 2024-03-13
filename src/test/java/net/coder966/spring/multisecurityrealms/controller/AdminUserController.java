package net.coder966.spring.multisecurityrealms.controller;

import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminUserController {

    @PreAuthorize("permitRealm('ADMIN_USER')")
    @GetMapping("/admin-user/my-name")
    public String myName(@AuthenticationPrincipal AdminUser adminUser) {
        return adminUser.getName();
    }

    @GetMapping("/admin-user/no-pre-authorize")
    public String noPreAuthorize() {
        return "This should be protected even though the developer did not annotated it with @PreAuthorize(\"permitRealm('ADMIN_USER')\")";
    }
}
