// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/shared/Constants.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget compatibility metadata

package io.github.ryuuseiakira.locket.patches.shared

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.FormFactor

object Constants {
    val COMPATIBILITY_LOCKET = Compatibility(
        name = "Locket Widget",
        packageName = "com.locket.Locket",
        description = "Share live photos from your best friends right to your home screen.",
        apkFileType = ApkFileType.APKM,
        appIconColor = 0xFFB000,
        formFactor = FormFactor.MOBILE,
        targets = listOf(
            AppTarget(version = "1.247.1"),
            AppTarget(version = null, isExperimental = true),
        ),
    )
}
