package com.example.securityjwtdemo;

import com.example.securityjwtdemo.auth.AuthenticationService;
import com.example.securityjwtdemo.dto.RegisterRequest;
import com.example.securityjwtdemo.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityJwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityJwtDemoApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authService) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstName("Test")
					.lastName("Admin")
					.email("testadmin@email.com")
					.password("test1234!")
					.role(Role.ADMIN)
					.build();
			System.out.println("Admin token: " + authService.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstName("Test")
					.lastName("Manager")
					.email("testmanager@email.com")
					.password("test1234!")
					.role(Role.MANAGER)
					.build();
			System.out.println("Manager token: " + authService.register(manager).getAccessToken());
			var user = RegisterRequest.builder()
					.firstName("Test")
					.lastName("User")
					.email("testuser@email.com")
					.password("test1234!")
					.role(Role.USER)
					.build();
			System.out.println("User token: " + authService.register(user).getAccessToken());
		};
	}
}
