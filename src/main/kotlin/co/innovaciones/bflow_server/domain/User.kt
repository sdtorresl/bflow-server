package co.innovaciones.bflow_server.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EntityListeners
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.SequenceGenerator
import jakarta.persistence.Table
import java.time.OffsetDateTime
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener


@Entity
@Table(name = "Users")
@EntityListeners(AuditingEntityListener::class)
class User {

    @Id
    @Column(
        nullable = false,
        updatable = false
    )
    @SequenceGenerator(
        name = "user_primary_sequence",
        sequenceName = "user_primary_sequence",
        allocationSize = 1,
        initialValue = 10000
    )
    @GeneratedValue(
        strategy = GenerationType.SEQUENCE,
        generator = "user_primary_sequence"
    )
    var id: Long? = null

    @Column(nullable = false)
    var firstName: String? = null

    @Column(nullable = false)
    var lastName: String? = null

    @Column(
        nullable = false,
        unique = true
    )
    var username: String? = null

    @Column(nullable = false)
    var password: String? = null

    @Column(
        nullable = false,
        unique = true
    )
    var email: String? = null

    @Column
    var recoveryToken: String? = null

    @Column
    var recoveryTokenExpired: OffsetDateTime? = null

    @CreatedDate
    @Column(
        nullable = false,
        updatable = false
    )
    var dateCreated: OffsetDateTime? = null

    @LastModifiedDate
    @Column(nullable = false)
    var lastUpdated: OffsetDateTime? = null

    var tokenExpirationDate: OffsetDateTime? = null

}
