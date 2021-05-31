package org.dripto.spring.mvcsecurity.controller

import org.dripto.spring.mvcsecurity.jpa.AuthorityRepository
import org.dripto.spring.mvcsecurity.jpa.MyUserEntity
import org.dripto.spring.mvcsecurity.jpa.UserRepositories
import org.dripto.spring.mvcsecurity.security.MyUserDetails
import org.dripto.spring.mvcsecurity.security.jwt.JwtUtils
import org.springframework.http.HttpStatus
import org.springframework.http.HttpStatus.NO_CONTENT
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.LocalDateTime

@RestController
@RequestMapping("/registration")
class RegistrationController(
    val repo: UserRepositories,
    val authorityRepository: AuthorityRepository,
    val passwordEncoder: PasswordEncoder
) {
    @GetMapping
    fun page() = "please register"

    @PostMapping
    @ResponseStatus(NO_CONTENT)
    fun register(@RequestBody details: RegistrationRequest) {
        val authorities = details.roles.map {
            authorityRepository.findOrCreateByAuthority(authority = it.name)
        }.toSet()
        val entity = MyUserEntity.from(details, passwordEncoder, authorities)
        repo.save(entity)
    }

    @GetMapping("/token")
    fun token(): TokenResponse {
        val details = SecurityContextHolder.getContext().authentication.principal as MyUserDetails
        val expiration = LocalDateTime.now().plusMinutes(50)
        val token = JwtUtils.create(details.username, claims = mapOf("roles" to details.authorities.map { it.authority }), validTill = expiration)
        return TokenResponse(token, expiration)
    }

    data class RegistrationRequest(val username: String, val password: String, val roles: Set<Role>)
    data class TokenResponse(val token: String, val expiration: LocalDateTime)
}

enum class Role {
    USER, ADMIN;

    fun authority(): SimpleGrantedAuthority = SimpleGrantedAuthority("ROLE_$name")
}