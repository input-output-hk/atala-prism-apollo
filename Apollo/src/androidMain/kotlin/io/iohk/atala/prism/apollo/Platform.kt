package io.iohk.atala.prism.apollo

actual object Platform {
    actual val OS: String = "Android ${android.os.Build.VERSION.SDK_INT}"
}