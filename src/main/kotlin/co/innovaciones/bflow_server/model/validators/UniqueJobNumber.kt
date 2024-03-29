package co.innovaciones.bflow_server.model.validators

import jakarta.validation.Constraint
import jakarta.validation.Payload
import kotlin.reflect.KClass

@Target(AnnotationTarget.FIELD, AnnotationTarget.PROPERTY_SETTER)
@Retention(AnnotationRetention.RUNTIME)
@MustBeDocumented
@Constraint(validatedBy = [UniqueJobNumberValidator::class])
annotation class UniqueJobNumber(
    val message: String = "is already defined",
    val groups: Array<KClass<*>> = [],
    val payload: Array<KClass<out Payload>> = []
)