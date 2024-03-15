package net.coder966.spring.multisecurityrealms.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@Entity
@NoArgsConstructor
public class AdminUser {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    private String username;

    private String password;

    private String otp;

    private int loginCounter = 0;

    @OneToMany(mappedBy = "adminUser", fetch = FetchType.LAZY)
    private Set<Badge> badges = new HashSet<>();

    public AdminUser(String name, String username, String password, Set<Badge> badges) {
        this.name = name;
        this.username = username;
        this.password = password;
        this.badges = badges;
    }
}
