plugins {
    alias(libs.plugins.kotlin.jpa)
    alias(libs.plugins.ksp)
}

dependencies {
    api(project(":iam-identity"))
    // 로그인 위험 평가
    implementation(project(":iam-risk"))
    api("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    // 로그인·MFA 화면
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    // 패스키(WebAuthn) 로그인·등록
    api("org.springframework.security:spring-security-webauthn")
}
