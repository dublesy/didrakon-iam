plugins {
    alias(libs.plugins.kotlin.jpa)
    alias(libs.plugins.ksp)
}

dependencies {
    api(project(":iam-common"))
    // HR 연동 실행 기록의 결과 요약(JSON)
    implementation("tools.jackson.core:jackson-databind")
}
