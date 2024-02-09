package com.example.securityjwtdemo.exceptions;

import java.time.Instant;

public record ErrorMessage(
        Instant timestamp,
        String message
)  { }
