package co.innovaciones.bflow_server.service

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.JWTVerifier
import java.time.Duration
import java.time.Instant
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service


@Service
class JwtTokenService(
    @Value("\${jwt.secret}")
    secret: String
) {

    final var hmac512: Algorithm? = null

    final var verifier: JWTVerifier? = null
    init {
        this.hmac512 = Algorithm.HMAC512(secret)
        this.verifier = JWT.require(this.hmac512).build()
    }

    fun generateToken(userDetails: UserDetails): String {
        val now = Instant.now()
        return JWT.create()
            .withSubject(userDetails.username)
            .withIssuer("app")
            .withIssuedAt(now)
            .withExpiresAt(now.plusMillis(JWT_TOKEN_VALIDITY.toMillis()))
            .sign(this.hmac512)
    }

    fun validateTokenAndGetUsername(token: String): String? = try {
        verifier?.verify(token)?.subject
    } catch (verificationEx: JWTVerificationException) {
        log.warn("token invalid: {}", verificationEx.message)
        null
    }


    companion object {

        val log: Logger = LoggerFactory.getLogger(JwtTokenService::class.java)

        val JWT_TOKEN_VALIDITY: Duration = Duration.ofMinutes(20)

    }

}