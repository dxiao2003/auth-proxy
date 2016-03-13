package com.katapal.auth.proxy.test

import java.security.interfaces.RSAPrivateKey
import java.security.{KeyPairGenerator, SecureRandom, Key}

import java.time.Instant
import java.util.{Date, Base64}

import com.katapal.auth.jwt.JWTVerifier
import com.katapal.auth.proxy.{CacheClient, AuthProxyFilter}
import com.nimbusds.jose.crypto.{RSASSASigner, MACSigner}

import com.nimbusds.jose.{JWSAlgorithm, JWSSigner, JWSHeader}
import com.nimbusds.jwt.{SignedJWT, JWTClaimsSet}
import com.twitter.finagle.http.{Status, Request, Response}
import com.twitter.finagle.Service
import com.twitter.util.{Future, Await}
import com.typesafe.config.{Config, ConfigValueFactory, ConfigFactory}

import org.mockito.ArgumentMatcher

import org.scalatest.mock.MockitoSugar
import org.scalatest.{BeforeAndAfter, Matchers, FunSpec}
import org.mockito.Mockito._
import org.mockito.Matchers._

/**
  * Created by David on 2/23/2016.
  */

case class SatisfiesFunction[A](f: A => Boolean, msg: String) extends ArgumentMatcher[A] {
  def matches(x: Any): Boolean = f(x.asInstanceOf[A])
  override def toString: String = msg
}

class AuthProxyFilterSpec extends FunSpec with Matchers with MockitoSugar with BeforeAndAfter {
  val refConfig = ConfigFactory.load()
  val baseConfig = refConfig
    .withValue("auth-url", ConfigValueFactory.fromAnyRef("https://auth-server.com/jwt/"))
    .withValue("jwt.signers.1.issuer",  ConfigValueFactory.fromAnyRef("https://my-domain.com/"))
    .withValue("jwt.audience",  ConfigValueFactory.fromAnyRef("https://my-domain.com/"))

  val encoder = Base64.getEncoder

  def itShouldProxy(validJWT: String, invalidJWT: String, config: Config): Unit = {
    trait Fixture {
      val cacheClient = mock[CacheClient]
      val authService = mock[Service[Request, Response]]
      val httpReverseProxy = mock[Service[Request, Response]]
      val tokenVerifier = new JWTVerifier(config.getConfig("jwt"))
      val authProxyFilter = new AuthProxyFilter(config, cacheClient, tokenVerifier, authService)
      val authProxyService = authProxyFilter.andThen(httpReverseProxy)
    }

    it("should return 401 without token") {
      new Fixture {
        val r = Request("/")
        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 401
        }
        Await.ready(f)
      }
    }

    it("should return 401 with wrong authorization scheme") {
      new Fixture {
        val r = Request("/")
        r.authorization = "ajsldkfjalskdjf"
        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 401
          response.wwwAuthenticate should not be empty
          response.wwwAuthenticate.get shouldEqual config.getString("from-auth-scheme")
        }
        Await.ready(f)
      }
    }

    it("should return 403 with bad token") {
      new Fixture {
        val r = Request("/")
        val dummyToken = "asoifjoasidfjoaijf"
        r.authorization = config.getString("from-auth-scheme") + " " + dummyToken

        when(cacheClient.get(dummyToken)).thenReturn(Future.value(None))
        val matchesRequest = SatisfiesFunction(
          { request: Request => request != null && request.authorization == r.authorization },
          "matches authorization")

        when(authService.apply(argThat(matchesRequest))).thenReturn(Future.value(Response(Status(403))))

        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 403
        }

        Await.ready(f)

        verify(cacheClient).get(dummyToken)
        verify(authService).apply(argThat(matchesRequest))
      }
    }

    it("should forward request with JWT with good token when cache misses") {
      new Fixture {
        val r = Request("/")
        val dummyToken = "asoifjoasidfjoaijf"
        val authHeader = config.getString("from-auth-scheme") + " " + dummyToken
        r.authorization = authHeader

        when(cacheClient.get(dummyToken)).thenReturn(Future.value(None))
        when(cacheClient.set(dummyToken, validJWT)).thenReturn(Future.value(()))
        val jwtResponse = Response(Status(200))
        jwtResponse.contentString = "{\"token\": \"" + validJWT + "\"}"

        val matchesRequest = SatisfiesFunction(
          { request: Request => request != null && request.authorization.getOrElse("") == authHeader },
          "matches authorization"
        )


        when(authService.apply(argThat(matchesRequest))).thenReturn(Future.value(jwtResponse))

        val proxyResponse = Response(Status(200))
        proxyResponse.contentString = "OK"
        val matchesOnwardRequest = SatisfiesFunction(
          { request: Request =>
            request != null &&
              request.authorization.getOrElse("") == config.getString("to-auth-scheme") + " " + validJWT
          },
          "has JWT")
        when(httpReverseProxy.apply(argThat(matchesOnwardRequest))).thenReturn(Future.value(proxyResponse))

        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 200
          response.contentString shouldEqual "OK"
        }

        Await.ready(f)

        verify(cacheClient).get(dummyToken)
        verify(cacheClient).set(dummyToken, validJWT)
        verify(authService).apply(argThat(matchesRequest))
        verify(httpReverseProxy).apply(argThat(matchesOnwardRequest))
      }
    }

    it("should forward request with JWT with good token when cache hits") {
      new Fixture {
        val r = Request("/")
        val dummyToken = "asoifjoasidfjoaijf"
        val authHeader = config.getString("from-auth-scheme") + " " + dummyToken
        r.authorization = authHeader

        when(cacheClient.get(dummyToken)).thenReturn(Future.value(Some(validJWT)))

        val proxyResponse = Response(Status(200))
        proxyResponse.contentString = "OK"
        val matchesOnwardRequest = SatisfiesFunction(
          { request: Request =>
            request != null &&
              request.authorization.getOrElse("") == config.getString("to-auth-scheme") + " " + validJWT
          },
          "has JWT")
        when(httpReverseProxy.apply(argThat(matchesOnwardRequest))).thenReturn(Future.value(proxyResponse))

        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 200
          response.contentString shouldEqual "OK"
        }

        Await.ready(f)

        verify(cacheClient).get(dummyToken)
        verify(cacheClient, never()).set(dummyToken, validJWT)
        verify(httpReverseProxy).apply(argThat(matchesOnwardRequest))
      }
    }

    it("should return 500 if auth server's JWT fails to verify when cache misses") {
      new Fixture {
        val r = Request("/")
        val dummyToken = "asoifjoasidfjoaijf"
        val authHeader = config.getString("from-auth-scheme") + " " + dummyToken
        r.authorization = authHeader

        when(cacheClient.get(dummyToken)).thenReturn(Future.value(None))
        val jwtResponse = Response(Status(200))
        jwtResponse.contentString = "{\"token\": \"" + invalidJWT + "\"}"

        val matchesRequest = SatisfiesFunction(
          { request: Request => request != null && request.authorization.getOrElse("") == authHeader },
          "matches authorization"
        )

        when(authService.apply(argThat(matchesRequest))).thenReturn(Future.value(jwtResponse))

        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 500
        }

        Await.ready(f)

        verify(cacheClient).get(dummyToken)
        verify(cacheClient, never()).set(dummyToken, invalidJWT)
        verify(authService).apply(argThat(matchesRequest))
      }
    }

    it("should refresh token if JWT in cache fails to verify") {
      new Fixture {
        val r = Request("/")
        val dummyToken = "asoifjoasidfjoaijf"
        val authHeader = config.getString("from-auth-scheme") + " " + dummyToken
        r.authorization = authHeader

        when(cacheClient.get(dummyToken)).thenReturn(Future.value(Some(invalidJWT)))
        when(cacheClient.set(dummyToken, validJWT)).thenReturn(Future.value(()))
        val jwtResponse = Response(Status(200))
        jwtResponse.contentString = "{\"token\": \"" + validJWT + "\"}"

        val matchesRequest = SatisfiesFunction(
          { request: Request => request != null && request.authorization.getOrElse("") == authHeader },
          "matches authorization"
        )


        when(authService.apply(argThat(matchesRequest))).thenReturn(Future.value(jwtResponse))

        val proxyResponse = Response(Status(200))
        proxyResponse.contentString = "OK"
        val matchesOnwardRequest = SatisfiesFunction(
          { request: Request =>
            request != null &&
              request.authorization.getOrElse("") == config.getString("to-auth-scheme") + " " + validJWT
          },
          "has JWT")
        when(httpReverseProxy.apply(argThat(matchesOnwardRequest))).thenReturn(Future.value(proxyResponse))

        val f = authProxyService(r) map { response =>
          response.statusCode shouldEqual 200
          response.contentString shouldEqual "OK"
        }

        Await.ready(f)

        verify(cacheClient).get(dummyToken)
        verify(cacheClient).set(dummyToken, validJWT)
        verify(authService).apply(argThat(matchesRequest))
        verify(httpReverseProxy).apply(argThat(matchesOnwardRequest))
      }
    }
  }

  def generateJWT(expirationTimeInFuture: Int, signer: JWSSigner, alg: JWSAlgorithm, config: Config) = {
    val now = Instant.now()
    val claims = new JWTClaimsSet.Builder()
      .issuer(config.getString("jwt.signers.1.issuer"))  // who creates the token and signs it
      .audience(config.getString("jwt.audience")) // to whom the token is intended to be sent
      .expirationTime(Date.from(now.plusSeconds(expirationTimeInFuture * 60))) // time when the token will expire
      .issueTime(new Date())
      .notBeforeTime(Date.from(now.minusSeconds(120))) // time before which the token is not yet valid (2 minutes ago)
      .subject("subject") // the subject/principal is whom the token is about
      .claim("uid","12345678") // additional claims/attributes about the subject can be added
      .build()

    val header = new JWSHeader.Builder(alg)
      .keyID("1")
      .build()

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    val signedJWT = new SignedJWT(header, claims)

    signedJWT.sign(signer)
    signedJWT.serialize
  }

  describe("An AuthProxyFilter") {
    describe("using HS256") {
      val random = new SecureRandom()
      val keyBytes = random.generateSeed(256)
      val signer = new MACSigner(keyBytes)
      val encodedKey = encoder.encodeToString(keyBytes)
      val config = baseConfig
        .withValue("jwt.signers.1.algorithm", ConfigValueFactory.fromAnyRef("HS256"))
        .withValue("jwt.signers.1.verification-key", ConfigValueFactory.fromAnyRef(encodedKey))
      // Create the Claims, which will be the content of the JWT
      val validJWT = generateJWT(10, signer, JWSAlgorithm.HS256, config)
      val invalidJWT = generateJWT(-1, signer, JWSAlgorithm.HS256, config)

      itShouldProxy(validJWT, invalidJWT, config)
    }

    describe("using RS256") {
      // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
      val keyGen = KeyPairGenerator.getInstance("RSA")
      keyGen.initialize(512)
      val kp = keyGen.generateKeyPair()
      val secretKey = kp.getPrivate.asInstanceOf[RSAPrivateKey]
      val signer = new RSASSASigner(secretKey)
      val publicKey = kp.getPublic
      val keyBytes = publicKey.getEncoded

      val config = baseConfig
        .withValue("jwt.signers.1.algorithm", ConfigValueFactory.fromAnyRef("RS256"))
        .withValue(
          "jwt.signers.1.verification-key",
          ConfigValueFactory.fromAnyRef(encoder.encodeToString(keyBytes))
        )
      // Create the Claims, which will be the content of the JWT
      val validJWT = generateJWT(10, signer, JWSAlgorithm.RS256, config)
      val invalidJWT = generateJWT(-1, signer, JWSAlgorithm.RS256, config)

      itShouldProxy(validJWT, invalidJWT, config)
    }
  }
}
