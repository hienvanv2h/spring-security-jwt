package com.example.securityjwtdemo.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/management")
public class ManagementController {

    @GetMapping()
    public String get() {
        return "GET - Management End Point";
    }

    @PostMapping()
    public String post() {
        return "POST - Management End Point";
    }

    @PutMapping()
    public String put() {
        return "PUT - Management End Point";
    }

    @DeleteMapping()
    public String delete() {
        return "DELETE - Management End Point";
    }
}
