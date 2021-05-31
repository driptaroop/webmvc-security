package org.dripto.spring.mvcsecurity

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.data.jpa.repository.config.EnableJpaRepositories
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

@SpringBootApplication
@EnableJpaRepositories
class MvcSecurityApplication{
    @Bean
    fun encoder(): PasswordEncoder = Argon2PasswordEncoder()
}

fun main(args: Array<String>) {
    runApplication<MvcSecurityApplication>(*args)
}
