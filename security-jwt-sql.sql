CREATE DATABASE `jwt_security` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `jwt_security`;
CREATE TABLE `users` (
	`id` bigint NOT NULL AUTO_INCREMENT,
    `email` varchar(50) UNIQUE DEFAULT NULL ,
    `first_name` varchar(50) DEFAULT NULL ,
    `last_name` varchar(50) DEFAULT NULL ,
    `password` char(68) DEFAULT NULL ,
    `role` enum('USER','ADMIN'),
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `token` (
	`id` bigint NOT NULL AUTO_INCREMENT,
    `token` varchar(255) UNIQUE DEFAULT NULL,
    `token_type` enum('BEARER') DEFAULT NULL ,
    `expired` bit(1) DEFAULT NULL,
    `revoked` bit(1) DEFAULT NULL,
    `user_id` bigint DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `token_fk` (`user_id`),
	CONSTRAINT `token_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
