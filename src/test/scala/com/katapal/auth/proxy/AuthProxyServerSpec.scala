package com.katapal.auth.proxy

import java.io.File
import java.util.UUID

import com.twitter.finagle.{Http, Service}
import com.twitter.finagle.http.{Request, RequestBuilder, Response, Status}
import com.twitter.io.Buf
import com.twitter.util.{Await, Future}
import com.typesafe.config.ConfigFactory
import org.scalatest.mock.MockitoSugar
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach, FunSpec, Matchers}
import org.mockito.Mockito._
import org.mockito.Matchers._

/**
  * Created by David on 4/1/2016.
  */
class AuthProxyServerSpec extends FunSpec with Matchers with BeforeAndAfterAll with BeforeAndAfterEach
  with MockitoSugar with GenerateJWT {

  val proxyConfig = AuthProxyServer.validateConfig(ConfigFactory.parseFile(new File("tests/application.conf")))
  val proxyServer = AuthProxyServer.startServer(proxyConfig)

  val config = ConfigFactory.parseFile(new File("tests/spec.conf"))
  val authService = mock[Service[Request, Response]]
  val authServer = Http.serve(s":${config.getInt("auth.port")}", authService)
  val destService = mock[Service[Request, Response]]
  val destServer = Http.serve(s":${config.getInt("dest.port")}", destService)
  val client = Http.client.newService(s"${config.getString("proxy.host")}:${config.getInt("proxy.port")}")

  override def afterAll: Unit = {
    Await.ready(proxyServer.close())
    Await.ready(authServer.close())
    Await.ready(destServer.close())
  }

  override def afterEach = {
    reset(authService)
    reset(destService)
  }

  val fromAuthScheme = proxyConfig.getString("from-auth-scheme")
  val toAuthScheme = proxyConfig.getString("to-auth-scheme")

  def buildRequest(content: String) = {
    val req = RequestBuilder()
      .url(s"http://localhost/")
      .buildPost(Buf.Utf8(content))
    val token = UUID.randomUUID.toString
    val header = s"$fromAuthScheme $token"
    req.authorization = header
    req
  }

  def buildAuthResponse(uid: String) = {
    val authResp = Response(status=Status.Ok)
    authResp.setContentTypeJson()
    val (signer, alg) = loadSignerAndAlg(config)
    val jwt = generateJWT(
      config.getConfig("jwt"), signer, alg, config.getString("key-id"), minutesInFuture(10), uid=uid
    )
    authResp.setContentString(s"""{"${proxyConfig.getString("auth-response-param")}": "$jwt" }""")
    (authResp, jwt)
  }

  describe("An AuthProxyServer") {
    it("should look up an auth token and forward the request") {
      val content = "request"
      val req = buildRequest(content)
      val (authResp, jwt) = buildAuthResponse("user")
      when(authService.apply(argThat(SatisfiesFunction(
        { r: Request => r.authorization == req.authorization },
        "matches expected auth request"
      )))).thenReturn(Future.value(authResp))
      val destResp = Response(status=Status.Ok)
      destResp.setContentString("ok")
      when(destService.apply(argThat(SatisfiesFunction(
        { req: Request =>
          req.authorization.isDefined && req.authorization.get == s"$toAuthScheme $jwt" &&
          req.contentString == content
        },
        "matches expected dest request"
      )))).thenReturn(Future.value(destResp))
      val f = client(req)
      val r = Await.result(f)
      r.statusCode shouldBe 200
      r.contentString shouldBe "ok"
    }

    it("should return 403 when auth token not found") {
      val content = "request"
      val req = buildRequest(content)
      val authResp = Response(status=Status.Forbidden)
      when(authService.apply(argThat(SatisfiesFunction(
        { r: Request => r.authorization == req.authorization },
        "matches expected auth request"
      )))).thenReturn(Future.value(authResp))
      val f = client(req)
      val r = Await.result(f)
      verify(destService, never()).apply(any())
      r.statusCode shouldBe 403
    }

    it("should return 401 when no auth set") {
      val content = "request"
      val req = RequestBuilder()
        .url(s"http://localhost/")
        .buildPost(Buf.Utf8(content))
      val authResp = Response(status=Status.Unauthorized)
      when(authService.apply(argThat(SatisfiesFunction(
        { r: Request => r.authorization.isEmpty },
        "matches expected auth request"
      )))).thenReturn(Future.value(authResp))
      val f = client(req)
      val r = Await.result(f)
      verify(destService, never()).apply(any())
      r.statusCode shouldBe 401
      r.wwwAuthenticate should contain (s"$fromAuthScheme")
    }
  }
}
