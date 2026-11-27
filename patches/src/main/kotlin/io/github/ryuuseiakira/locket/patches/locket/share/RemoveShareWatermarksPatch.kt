// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/share/RemoveShareWatermarksPatch.kt
// Kotlin / Morphe Patcher (JVM 11, Android API 26) / Locket Widget Remove share watermarks patch

package io.github.ryuuseiakira.locket.patches.locket.share

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.instructions
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET

private val imageMarkerDrawFingerprint = Fingerprint(
    definingClass = "Lcom/jimmydaddy/imagemarker/a;",
    returnType = "Landroid/graphics/Bitmap;",
    strings = listOf("Watermark bitmap at index "),
)

/**
 * Strips overlay watermark images from `ImageMarker.markWithImage` shares while preserving
 * background scaling, compression, text markers, and Promise file resolution.
 *
 * Attachment: Watermark array getter resolved dynamically from `com.jimmydaddy.imagemarker.a`
 * (`Ldf/d;->f()[Ldf/t;` in `1.247.1`).
 * Mechanism: Returns a zero-length typed overlay array before Glide downloads or Canvas composites
 * any watermark bitmap onto the shared image.
 * Constraint: Opt-in (`default = false`); resolves the R8-renamed getter via signature/reference
 * inside the un-obfuscated `ImageMarker` bitmap composer so future R8 renames still resolve.
 */
@Suppress("unused")
val removeShareWatermarksPatch = patch(
    name = "Remove share watermarks",
    description = "Strips Locket overlay watermarks from shared History and Moment images while preserving normal saving and scaling.",
    default = false,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    dependsOn(spoofSignaturePatch)

    execute {
        val composerMethod = imageMarkerDrawFingerprint.originalMethod
        val arrayGetters = composerMethod.instructions
            .mapNotNull { (it as? ReferenceInstruction)?.reference as? MethodReference }
            .filter { ref ->
                ref.name != "<init>" &&
                    ref.parameterTypes.isEmpty() &&
                    ref.returnType.startsWith("[L")
            }
            .distinctBy { "${it.definingClass}->${it.name}${it.returnType}" }

        if (arrayGetters.size != 1) {
            throw PatchException(
                "Expected 1 watermark overlay array getter in ${composerMethod.definingClass}, found ${arrayGetters.size}."
            )
        }

        val targetRef = arrayGetters[0]
        val targetClass = mutableClassDefBy(targetRef.definingClass)
        val targetMethod = targetClass.methods.firstOrNull { method ->
            method.name == targetRef.name &&
                method.parameterTypes.isEmpty() &&
                method.returnType == targetRef.returnType
        } ?: throw PatchException(
            "Unable to locate mutable watermark getter ${targetRef.definingClass}->${targetRef.name}()${targetRef.returnType}."
        )

        targetMethod.addInstructions(
            0,
            """
                const/4 v0, 0x0
                new-array v0, v0, ${targetMethod.returnType}
                return-object v0
            """.trimIndent(),
        )
    }
}
