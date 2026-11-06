import io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension
import org.jetbrains.kotlin.allopen.gradle.AllOpenExtension
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension
import org.springframework.boot.gradle.plugin.SpringBootPlugin

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.spring) apply false
    alias(libs.plugins.kotlin.jpa) apply false
    alias(libs.plugins.spring.boot) apply false
    alias(libs.plugins.spring.dependency.management) apply false
    alias(libs.plugins.ksp) apply false
}

// subprojects 블록 안에서는 libs 접근자를 쓸 수 없어 미리 받아둔다
val catalog = libs

subprojects {
    group = "com.didrakon.iam"
    version = "0.0.1-SNAPSHOT"

    apply(plugin = "java-library")
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "org.jetbrains.kotlin.plugin.spring")
    apply(plugin = "io.spring.dependency-management")

    // Boot BOM 의 kotlin.version(2.3.x)이 Kotlin 컴파일러까지 다운그레이드하지 않도록 플러그인 버전에 맞춘다
    extra["kotlin.version"] = catalog.versions.kotlin.get()

    configure<DependencyManagementExtension> {
        imports { mavenBom(SpringBootPlugin.BOM_COORDINATES) }
    }

    configure<KotlinJvmProjectExtension> {
        jvmToolchain(25)
        compilerOptions {
            freeCompilerArgs.add("-Xjsr305=strict")
        }
    }

    dependencies {
        "implementation"("org.jetbrains.kotlin:kotlin-reflect")
        "testImplementation"("org.springframework.boot:spring-boot-starter-test")
        "testImplementation"("org.jetbrains.kotlin:kotlin-test-junit5")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    // 엔티티를 가진 모듈은 kotlin-jpa 플러그인만 선언하면 JPA·QueryDSL 설정이 함께 적용된다
    pluginManager.withPlugin("org.jetbrains.kotlin.plugin.jpa") {
        configure<AllOpenExtension> {
            annotation("jakarta.persistence.Entity")
            annotation("jakarta.persistence.MappedSuperclass")
            annotation("jakarta.persistence.Embeddable")
        }
        dependencies {
            "api"("org.springframework.boot:spring-boot-starter-data-jpa")
            "api"(catalog.querydsl.jpa)
        }
    }

    pluginManager.withPlugin("com.google.devtools.ksp") {
        dependencies {
            "ksp"(catalog.querydsl.ksp.codegen)
        }
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}
