package com.katapal.auth.proxy

import java.net.URL

import com.twitter.finagle.{Service, SimpleFilter}
import com.twitter.finagle.http.{Status, Request, Response}
import com.twitter.util.Future
import com.typesafe.config.Config

import scala.util.{Failure, Success}
import scala.util.parsing.json.JSON
import com.katapal.auth.{TokenVerifier => Verifier}

/**
  * Created by David on 2/23/2016.
  */
class AuthProxyFilter(protected val config: Config,
                      protected val cacheClient: CacheClient,
                      protected val tokenVerifier: Verifier,
                      protected val authService: Service[Request, Response])
  extends SimpleFilter[Request, Response] {

  protected val authUrl = new URL(config.getString("auth-url"))
  protected val fromAuthScheme = config.getString("from-auth-scheme")
  protected val toAuthScheme = config.getString("to-auth-scheme")

  override def apply(request: Request, service: Service[Request, Response]): Future[Response] = {
    // get authorization and see if it is the from auth type
    val validAuth: Option[String] = request.authorization flatMap { s: String =>
      val parts = s.split("\\s+", 2)
      if (parts(0) == fromAuthScheme)
        Some(parts(1))
      else
        None
    }

    validAuth match {
      case None =>
        // if authorization is missing or wrong type, return 401 and set WWW-authenticate header
        val r = Response(Status(401))
        r.wwwAuthenticate = fromAuthScheme
        Future.value(r)
      case Some(fromToken) =>
        try {
          for {
          // if authorization found and right type, check cache
            cacheResult <- cacheClient.get(fromToken)
            // get the toToken from this cache result
            t <- getToToken(fromToken, cacheResult)
            // update the request and send it to the service
            response <- service(setRequestAuthorization(request, t))
          } yield response
        } catch {
          case AuthServerException(authResponse, msg) =>
            if (authResponse.statusCode == 403)
              Future.value(Response(Status(403)))
            else if (authResponse.statusCode == 401) {
              val response = Response(Status(401))
              response.wwwAuthenticate = authResponse.wwwAuthenticate.getOrElse(fromAuthScheme)
              Future.value(response)
            } else
              Future.value(Response(Status(500)))
        }
    }
  }

  def makeToToken(s: String): Option[String] = {
    tokenVerifier.verify(s) match {
      case Success(_) => Some(s)
      case Failure(_) => None
    }
  }

  def getToTokenFromAuthServer(fromToken: String): Future[String] = {
    val authRequest = Request(authUrl.getPath)
    authRequest.authorization = fromAuthScheme + " " + fromToken

    authService(authRequest) map { authResponse =>
      authResponse.status match {
        case Status(200) =>
          // if success, cache token and construct new request
          JSON.parseFull(authResponse.contentString) match {
            case None =>
              throw AuthServerException(authResponse, "Invalid data")
            case Some(x) =>
              try {
                val data = x.asInstanceOf[Map[String, String]]
                data(config.getString("auth-response-param")) match {
                  case toToken if tokenVerifier.verify(toToken).isSuccess => toToken
                  case _ => throw AuthServerException(authResponse, "Failed to verify JWT")
                }
              } catch {
                case e: Throwable =>
                  throw AuthServerException(authResponse, "Invalid data")
              }
          }
        case _ =>
          throw AuthServerException(authResponse)
      }
    }
  }

  def getToToken(fromToken: String, cacheResult: Option[String]): Future[String] = {
    cacheResult flatMap makeToToken match {
      // if checks pass, return the cached toToken
      case Some(toToken) =>
        Future.value(toToken)

      // if checks fail, get new toToken from auth server
      case None =>
        for {
          toToken <- getToTokenFromAuthServer(fromToken)
          cacheResponse <- cacheClient.set(fromToken, toToken)
        } yield toToken
    }
  }

  def setRequestAuthorization(req: Request, token: String): Request = {
    req.authorization = toAuthScheme + " " + token
    req
  }
}

case class AuthServerException(authResponse: Response,
                               msg: String = "Auth server error") extends Exception
