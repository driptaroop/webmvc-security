package org.dripto.spring.mvcsecurity.security.filter

import org.dripto.spring.mvcsecurity.security.MyUserDetails
import org.dripto.spring.mvcsecurity.security.MyUserDetailsService
import org.dripto.spring.mvcsecurity.security.jwt.JwtUtils
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtFilter(
    val userDetailsService: MyUserDetailsService
) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader: String? = request.getHeader("Authorization")

        if (authHeader != null && authHeader.startsWith("Bearer")) {
            processAuthHeader(authHeader, request)
        }
        filterChain.doFilter(request, response)
    }

    private fun processAuthHeader(authHeader: String, request: HttpServletRequest){
        val jwt: String = authHeader.substring(7)
        val username: String? = JwtUtils.extractUserName(jwt)
        if (username != null && SecurityContextHolder.getContext().authentication == null) {
            validateToken(jwt, username, request)
        }
    }

    private fun validateToken(jwt: String, username: String, request: HttpServletRequest) {
        val user = userDetailsService.loadUserByUsername(username) as MyUserDetails
        if (JwtUtils.validate(jwt, user)) {
            setupAuth(user, request)
        }
    }

    private fun setupAuth(user: MyUserDetails, request: HttpServletRequest) {
        val upToken = UsernamePasswordAuthenticationToken(user, user.password, user.authorities)
        upToken.details = WebAuthenticationDetailsSource().buildDetails(request)
        SecurityContextHolder.getContext().authentication = upToken
    }
}