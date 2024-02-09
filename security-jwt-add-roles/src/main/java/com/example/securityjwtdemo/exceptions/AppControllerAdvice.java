package com.example.securityjwtdemo.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.Instant;

@ControllerAdvice
public class AppControllerAdvice extends ResponseEntityExceptionHandler {

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<?> handleRefreshTokenException(RefreshTokenException exc) throws Exception {
        return handleException(exc);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception exc) throws Exception {

        HttpStatus status;
        ErrorMessage errorMessage;
        if(exc instanceof RefreshTokenException) {
            status = HttpStatus.UNAUTHORIZED;
        } else {
            throw exc;
        }
        errorMessage = new ErrorMessage(Instant.now(), exc.getMessage());
        return new ResponseEntity<>(errorMessage, status);
    }
}
