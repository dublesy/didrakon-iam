plugins {
    // 로컬에 없는 JDK(toolchain)를 자동으로 내려받는다
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "didrakon-iam"

include(
    "iam-common",
    "iam-identity",
    "iam-authn",
    "iam-authz",
    "iam-governance",
    "iam-risk",
    "iam-audit",
    "iam-app",
)
