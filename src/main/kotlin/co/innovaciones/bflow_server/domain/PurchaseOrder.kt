package co.innovaciones.bflow_server.domain

import co.innovaciones.bflow_server.model.OrderStatus
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EntityListeners
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.FetchType
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.ManyToOne
import jakarta.persistence.OneToMany
import jakarta.persistence.SequenceGenerator
import jakarta.persistence.Table
import java.time.LocalDateTime
import java.time.OffsetDateTime
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener


@Entity
@Table(name = "PurchaseOrders")
@EntityListeners(AuditingEntityListener::class)
class PurchaseOrder {

    @Id
    @Column(
        nullable = false,
        updatable = false
    )
    @SequenceGenerator(
        name = "po_primary_sequence",
        sequenceName = "po_primary_sequence",
        allocationSize = 1,
        initialValue = 10000
    )
    @GeneratedValue(
        strategy = GenerationType.SEQUENCE,
        generator = "po_primary_sequence"
    )
    var id: Long? = null

    @Column(
        nullable = false,
        unique = true
    )
    var number: String? = null

    @Column
    var sentDate: LocalDateTime? = null

    @Column
    var approvedDate: LocalDateTime? = null

    @Column
    var completedDate: LocalDateTime? = null

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    var status: OrderStatus? = null

    @OneToMany(mappedBy = "purchaseOrder")
    var orderItems: MutableSet<Item>? = null

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "job_id")
    var job: Job? = null

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "supplier_id")
    var supplier: Contact? = null

    @CreatedDate
    @Column(
        nullable = false,
        updatable = false
    )
    var dateCreated: OffsetDateTime? = null

    @LastModifiedDate
    @Column(nullable = false)
    var lastUpdated: OffsetDateTime? = null

}
