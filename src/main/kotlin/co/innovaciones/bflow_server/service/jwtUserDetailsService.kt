package co.innovaciones.bflow_server.service

import co.innovaciones.bflow_server.model.JwtUserDetails
import co.innovaciones.bflow_server.model.UsersRole
import co.innovaciones.bflow_server.repos.UserRepository
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service


@Service
class JwtUserDetailsService(
    private val userRepository: UserRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): JwtUserDetails {
        val user = userRepository.findByUsernameIgnoreCase(username)
        if (user.isEmpty) {
            log.warn("user not found: {}", username)
            throw UsernameNotFoundException("User $username not found")
        }
        val authorities = listOf(SimpleGrantedAuthority(UsersRole.ADMIN.name))
        return JwtUserDetails(user.get().id, username, user.get().password, authorities)
    }

    companion object {
        val log: Logger = LoggerFactory.getLogger(JwtUserDetailsService::class.java)
    }

}