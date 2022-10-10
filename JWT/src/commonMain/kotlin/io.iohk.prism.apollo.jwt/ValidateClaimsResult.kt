package io.iohk.prism.apollo.jwt

/**
 * ValidateClaimsResult list the possible results of a call to JWT.validateClaims method.
 */
enum class ValidateClaimsResult(val description: String) {
    /**
     * Successful validation.
     */
    SUCCESS("Success"),

    /**
     * Invalid Expiration claim.
     */
    INVALID_EXPIRATION("Invalid Expiration claim"),

    /**
     * Expired token: expiration time claim is in the past.
     */
    EXPIRED("Expired token"),

    /**
     * Invalid Not Before claim.
     */
    INVALID_NOT_BEFORE("Invalid Not Before claim"),

    /**
     * Not Before claim is in the future.
     */
    NOT_BEFORE("Token is not valid yet, Not Before claim is greater than the current time"),

    /**
     * Invalid Issued At claim.
     */
    INVALID_ISSUED_AT("Invalid Issued At claim"),

    /**
     * Issued At claim is in the future.
     */
    ISSUED_AT("Issued At claim is greater than the current time");
}