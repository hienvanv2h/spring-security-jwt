package com.example.securityjwtdemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @GetMapping()
    @PreAuthorize("hasAuthority('admin:read')")
    public String getAdmin() {
        return "GET - Admin End Point";
    }

    @PostMapping()
    @PreAuthorize("hasAuthority('admin:create')")
    public String postAdmin() {
        return "POST - Admin End Point";
    }

    @PutMapping()
    @PreAuthorize("hasAuthority('admin:update')")
    public String putAdmin() {
        return "PUT - Admin End Point";
    }

    @DeleteMapping()
    @PreAuthorize("hasAuthority('admin:delete')")
    public String deleteAdmin() {
        return "DELETE - Admin End Point";
    }
}
