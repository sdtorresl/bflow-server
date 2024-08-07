package co.innovaciones.bflow_server.model

import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size


class ItemDTO {

    var id: Long? = null

    @NotNull
    @Size(max = 255)
    var name: String? = null

    var description: String? = null

    @NotNull
    var unitPrice: Double? = null

    var vat: Double? = null

    var price: Double? = null

    @NotNull
    var units: Long? = null

    var measure: Units? = null

    var purchaseOrder: Long? = null

    @NotNull
    var supplier: Long? = null

    @NotNull
    var category: Long? = null

    @NotNull
    var job: Long? = null

}
