package es.sergomz.securitysample

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SecuritySampleApplication

fun main(args: Array<String>) {
	runApplication<SecuritySampleApplication>(*args)
}
