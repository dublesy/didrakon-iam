plugins {
    alias(libs.plugins.kotlin.jpa)
    alias(libs.plugins.ksp)
}

dependencies {
    api(project(":iam-authz"))
    // 접근 요청 위험 평가
    implementation(project(":iam-risk"))
}
