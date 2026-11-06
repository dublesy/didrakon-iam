plugins {
    alias(libs.plugins.kotlin.jpa)
    alias(libs.plugins.ksp)
}

dependencies {
    api(project(":iam-identity"))
    // 판정 시 위험 점수 (CONTEXT.riskScore)
    implementation(project(":iam-risk"))
    // ABAC 규칙 값(JSON)과 판정 근거 직렬화
    implementation("tools.jackson.core:jackson-databind")
}
