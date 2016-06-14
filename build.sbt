import com.amazonaws.auth.profile.ProfileCredentialsProvider
import com.amazonaws.services.s3.model.{CannedAccessControlList, Region}

name := "auth-proxy"

version := "0.0.1"

scalaVersion := "2.11.7"

resolvers += "twitter" at "https://maven.twttr.com"

libraryDependencies ++= Seq(
  "com.twitter" %% "finagle-http" % "6.33.0",
  "com.twitter" %% "finagle-redis" % "6.33.0",
  "com.nimbusds" % "nimbus-jose-jwt" % "4.12",
  "org.scalactic" %% "scalactic" % "2.2.6" % "test",
  "org.scalatest" %% "scalatest" % "2.2.6" % "test",
  "org.mockito" % "mockito-all" % "1.10.19" % "test",
  "com.typesafe" % "config" % "1.3.0",
  "org.slf4j" % "slf4j-api" % "1.7.18",
  "org.slf4j" % "slf4j-log4j12" % "1.7.18",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.1.0",
  "com.katapal" %% "auth" % "0.1.0"
)

enablePlugins(UniversalPlugin)

enablePlugins(RpmPlugin)

enablePlugins(DebianPlugin)

maintainer := "David Xiao <dxiao@katapal.com>"

packageSummary := "Katapal Auth Proxy"

packageDescription := "Katapal Auth Proxy"

rpmVendor := "katapal"

rpmLicense := Some("Copyright")

enablePlugins(JavaServerAppPackaging)

s3region := Region.US_Standard

awsProfile := "default"

s3acl := CannedAccessControlList.Private

s3credentials := new ProfileCredentialsProvider(awsProfile.value) |
  new ProfileCredentialsProvider("aws.credentials", awsProfile.value)

publishTo := Some(s3resolver.value("Katapal Maven s3 bucket", s3("maven.katapal.com")).withIvyPatterns)

resolvers += s3resolver.value("Katapal Maven S3 resolver", s3("maven.katapal.com")).withIvyPatterns