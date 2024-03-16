package com.example.spring.multisecurityrealms.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import java.util.HashSet;
import java.util.Set;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

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
    private Set<com.example.spring.multisecurityrealms.entity.Badge> badges = new HashSet<>();

    public AdminUser(String name, String username, String password, Set<com.example.spring.multisecurityrealms.entity.Badge> badges) {
        this.name = name;
        this.username = username;
        this.password = password;
        this.badges = badges;
    }
}
