package io.iohk.atala.prism.jwt

import io.iohk.prism.apollo.jwt.ClaimsStandardJWT
import io.iohk.prism.apollo.jwt.JWT
import io.iohk.prism.apollo.jwt.JWTSigner
import io.iohk.prism.apollo.jwt.JWTVerifier
import io.iohk.prism.apollo.jwt.ValidateClaimsResult
import kotlinx.datetime.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class JWTTests {

    @Test
    fun testSignAndVerifyNone() {
        try {
            signAndVerify(JWTSigner.none(), JWTVerifier.none())
        } catch (e: Exception) {
            fail("failed: ${e.message}")
        }
    }

    @Test
    fun testSignAndVerifyHMAC256() {
        val key = "Super Secret Key".encodeToByteArray()
        try {
            signAndVerify(JWTSigner.hs256(key), JWTVerifier.hs256(key))
        } catch (e: Exception) {
            fail("failed: ${e.message}")
        }
    }

    @Test
    fun testSignAndVerifyHMAC384() {
        val key = "Super Secret Key".encodeToByteArray()
        try {
            signAndVerify(JWTSigner.hs384(key), JWTVerifier.hs384(key))
        } catch (e: Exception) {
            fail("failed: ${e.message}")
        }
    }

    @Test
    fun testSignAndVerifyHMAC512() {
        val key = "Super Secret Key".encodeToByteArray()
        try {
            signAndVerify(JWTSigner.hs512(key), JWTVerifier.hs512(key))
        } catch (e: Exception) {
            fail("failed: ${e.message}")
        }
    }

    private fun signAndVerify(signer: JWTSigner, verifier: JWTVerifier) {
        val jwt = JWT(claims = ClaimsStandardJWT())
        jwt.claims.iss = "issuer"
        jwt.claims.aud = listOf("clientID")
        jwt.claims.iat = Instant.parse("2017-02-01T11:46:05Z").toEpochMilliseconds()
        jwt.claims.exp = Instant.parse("2048-10-10T13:32:45Z").toEpochMilliseconds()
        jwt.claims.nbf = Instant.parse("2017-02-01T11:46:05Z").toEpochMilliseconds()
        val signed = jwt.sign(signer)
        val ok = JWT.verify(signed, verifier)
        assertTrue(ok, "Verification failed")
        val decoded = JWT(signed)
        check(decoded, signer.name)
        assertEquals(decoded.validateClaims(), ValidateClaimsResult.SUCCESS, "Validation failed")
    }

    private fun check(jwt: JWT, algorithm: String) {
        assertEquals(jwt.header.alg, algorithm, "Wrong .alg in decoded")
        assertEquals(jwt.claims.exp, Instant.parse("2048-10-10T13:32:45Z").toEpochMilliseconds(), "Wrong .exp in decoded")
        assertEquals(jwt.claims.iat, Instant.parse("2017-02-01T11:46:05Z").toEpochMilliseconds(), "Wrong .iat in decoded")
        assertEquals(jwt.claims.nbf, Instant.parse("2017-02-01T11:46:05Z").toEpochMilliseconds(), "Wrong .nbf in decoded")
    }
}
