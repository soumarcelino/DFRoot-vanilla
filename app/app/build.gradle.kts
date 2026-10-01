plugins { id("com.android.application") }

android {
    namespace = "df.root"
    compileSdk = 36

    defaultConfig {
        applicationId = "df.root"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    sourceSets["main"].apply {
        jniLibs.srcDir("build/generated/jniLibs")
        assets.srcDir("build/generated/assets")
    }
}
