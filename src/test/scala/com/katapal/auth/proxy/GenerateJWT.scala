package com.katapal.auth.proxy

import java.security.{InvalidAlgorithmParameterException, KeyFactory}
import java.security.interfaces.{ECPrivateKey, RSAPrivateKey}
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.{Base64, Date}

import com.nimbusds.jose.crypto.{ECDSASigner, MACSigner, RSASSASigner}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader, JWSSigner}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.typesafe.config.Config

/**
  * Created by David on 4/1/2016.
  */
trait GenerateJWT {
  def minutesInFuture(m: Int) = {
    Instant.now.plusSeconds(m * 60)
  }
  def generateJWT(config: Config, signer: JWSSigner, alg: JWSAlgorithm, keyId: String,
                  expiration: Instant, uid: String = "1234", notBefore: Instant = Instant.now.minusSeconds(120)) = {

    val claims = new JWTClaimsSet.Builder()
      .issuer(config.getString(s"signers.$keyId.issuer"))  // who creates the token and signs it
      .audience(config.getString("audience")) // to whom the token is intended to be sent
      .expirationTime(Date.from(expiration)) // time when the token will expire
      .issueTime(new Date())
      .notBeforeTime(Date.from(notBefore)) // time before which the token is not yet valid (2 minutes ago)
      .subject("subject") // the subject/principal is whom the token is about
      .claim("uid", uid) // additional claims/attributes about the subject can be added
      .build()

    val header = new JWSHeader.Builder(alg)
      .keyID(keyId)
      .build()

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    val signedJWT = new SignedJWT(header, claims)

    signedJWT.sign(signer)
    signedJWT.serialize
  }

  def loadSignerAndAlg(config: Config): (JWSSigner, JWSAlgorithm) = {
    val keyId = config.getString("key-id")
    val alg = new JWSAlgorithm(config.getString(s"jwt.signers.$keyId.algorithm"))
    val keyBytes = Base64.getDecoder.decode(config.getString(s"jwt.signers.$keyId.signing-key"))

    val signer =
      if (alg.getName.startsWith("HS")) {
        new MACSigner(keyBytes)
      } else if (alg.getName.startsWith("RS")) {
        val keySpec = new PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        val k = kf.generatePrivate(keySpec).asInstanceOf[RSAPrivateKey]
        new RSASSASigner(k)
      } else if (alg.getName.startsWith("EC")) {
        val keySpec = new PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("EC")
        val k = kf.generatePrivate(keySpec).asInstanceOf[ECPrivateKey]
        new ECDSASigner(k)
      } else
        throw new InvalidAlgorithmParameterException(alg.getName)

    (signer, alg)
  }
}
