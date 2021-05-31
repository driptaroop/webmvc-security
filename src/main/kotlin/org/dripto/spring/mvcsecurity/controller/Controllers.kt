package org.dripto.spring.mvcsecurity.controller

import org.dripto.spring.mvcsecurity.security.MyUserDetails
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/user")
class UserController {
    @GetMapping fun page(): String {
        val user = SecurityContextHolder.getContext().authentication.principal as MyUserDetails
        return "hello user:${user.username} with id:${user.userId}"
    }
}

@RestController
@RequestMapping("/admin")
class AdminController {
    @GetMapping fun page() = "hello admin!!"
}

