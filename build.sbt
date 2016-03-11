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
  "com.typesafe" % "config" % "1.3.0"
)
