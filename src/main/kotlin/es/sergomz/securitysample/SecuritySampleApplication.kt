package es.sergomz.securitysample

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@SpringBootApplication
class SecuritySampleApplication

fun main(args: Array<String>) {
	runApplication<SecuritySampleApplication>(*args)
}
