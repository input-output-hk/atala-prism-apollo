package org.hyperledger.identus.apollo

/**
 * Provides information about the platform on which the application is running.
 */
expect object Platform {
    /**
     * Operating system name
     */
    val OS: String
}
