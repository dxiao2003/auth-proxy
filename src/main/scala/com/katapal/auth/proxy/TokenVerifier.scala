package com.katapal.auth.proxy

import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import java.security.{InvalidAlgorithmParameterException, KeyFactory, Key}
import java.security.spec.X509EncodedKeySpec
import java.util
import java.util.Base64

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.proc.{JWSKeySelector, SimpleSecurityContext}
import com.nimbusds.jwt.proc.{BadJWTException, DefaultJWTProcessor, DefaultJWTClaimsVerifier}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.typesafe.config.Config

import scala.util.{Success, Failure, Try}

/**
  * Created by David on 2/24/2016.
  */
trait TokenVerifier {
  def verify(token: String): Boolean
}

case class ProxyJWTVerifier(config: Config) extends TokenVerifier {

  protected val processor = new DefaultJWTProcessor[SimpleSecurityContext]
  protected val context = new SimpleSecurityContext()
  processor.setJWSKeySelector(new MyJWSKeySelector(config))
  processor.setJWTClaimsVerifier(new MyJWTClaimsVerifier(config))

  class MyJWTClaimsVerifier(config: Config) extends DefaultJWTClaimsVerifier {
    super.setMaxClockSkew(config.getInt("allowed-clock-skew"))

    override def verify(claims: JWTClaimsSet): Unit = {
      super.verify(claims)

      if (!claims.getAudience.contains(config.getString("audience")))
        throw new BadJWTException("Invalid audience")
      else if (claims.getIssuer != config.getString ("issuer"))
        throw new BadJWTException("Invalid issuer")
    }
  }

  class MyJWSKeySelector(config: Config) extends JWSKeySelector[SimpleSecurityContext] {
    protected val decoder = Base64.getDecoder
    protected val bytes = decoder.decode(config.getString("verification-key"))
    protected val algorithm = config.getString("algorithm")

    protected val myKey = if (algorithm.startsWith("HS")) {
      new MACVerifier(bytes).getSecretKey
    } else {
      val pubKeySpec = new X509EncodedKeySpec(bytes)
      if (algorithm.startsWith("RS")) {
        val kf = KeyFactory.getInstance("RSA")
        kf.generatePublic(pubKeySpec).asInstanceOf[RSAPublicKey]
      } else if (algorithm.startsWith("EC")) {
        val kf = KeyFactory.getInstance("EC")
        kf.generatePublic(pubKeySpec).asInstanceOf[ECPublicKey]
      } else
        throw new InvalidAlgorithmParameterException(algorithm)
    }

    def selectJWSKeys(header: JWSHeader, context: SimpleSecurityContext) = {
      val l = new util.LinkedList[Key]()
      l.add(myKey)
      l
    }
  }

  def verify(s: String): Boolean = {
      val signedJWT = SignedJWT.parse(s)
      val claimSet = signedJWT.getJWTClaimsSet

      Try(processor.process(signedJWT, context)) match {
        case Failure(e) => false
        case Success(_) => true
      }
  }

}