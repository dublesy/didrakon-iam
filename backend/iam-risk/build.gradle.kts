plugins {
    alias(libs.plugins.kotlin.jpa)
    alias(libs.plugins.ksp)
}

dependencies {
    api(project(":iam-identity"))
    // 위험 정책 조건(JSON) 해석
    implementation("tools.jackson.core:jackson-databind")
    // IP 국가 판별 (MaxMind GeoLite2/GeoIP2 Country .mmdb). iam.risk.geoip-database 를 넣었을 때만 쓴다
    implementation(libs.geoip2)
}
