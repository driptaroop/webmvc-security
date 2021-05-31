package org.dripto.spring.mvcsecurity.security

import org.dripto.spring.mvcsecurity.controller.Role
import org.dripto.spring.mvcsecurity.controller.Role.USER
import org.dripto.spring.mvcsecurity.jpa.UserRepositories
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class MyUserDetailsService(
    private val userRepositories: UserRepositories
): UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails =
        userRepositories.findByUsername(username)?.let {
            MyUserDetails(it.username, it.passwordHash, it.id, it.roles.map {role -> Role.valueOf(role.authority) }.toSet())
        } ?: throw UsernameNotFoundException("User Not Found").also { println(it) }
}

class MyUserDetails(
    username: String,
    password: String,
    val userId: UUID,
    authorities: Set<Role>
): User(username, password, authorities.map { it.authority() })