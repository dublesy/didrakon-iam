plugins {
    alias(libs.plugins.spring.boot)
}

dependencies {
    implementation(project(":iam-identity"))
    implementation(project(":iam-authn"))
    implementation(project(":iam-authz"))
    implementation(project(":iam-governance"))
    implementation(project(":iam-risk"))
    implementation(project(":iam-audit"))

    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    // 브라우저(HTTP) 세션을 DB 에 둔다: 재기동·배포에도 IdP 로그인이 유지되고 여러 인스턴스가 세션을 함께 쓴다
    implementation("org.springframework.boot:spring-boot-starter-session-jdbc")
    implementation("org.flywaydb:flyway-mysql")
    implementation(libs.shedlock.spring)
    implementation(libs.shedlock.jdbc)
    implementation("tools.jackson.module:jackson-module-kotlin")
    // 웹훅 전송: DNS 해석을 가로채 내부망 주소로는 접속 자체를 막는다 (JDK HttpClient 는 해석 단계를 바꿀 수 없다). 버전은 Spring Boot 가 관리
    implementation("org.apache.httpcomponents.client5:httpclient5")
    runtimeOnly("com.mysql:mysql-connector-j")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-mysql")
    // 패스키 등록·로그인 테스트용 가상 인증기. 버전은 spring-security-webauthn 이 쓰는 webauthn4j-core 와 맞춘다
    testImplementation("com.webauthn4j:webauthn4j-test:0.31.10.RELEASE")
}
