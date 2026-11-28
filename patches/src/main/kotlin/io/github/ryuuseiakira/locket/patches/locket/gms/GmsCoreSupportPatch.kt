// patches/src/main/kotlin/io/github/ryuuseiakira/locket/patches/locket/gms/GmsCoreSupportPatch.kt
// kotlin / GmsCoreSupportPatch / morphe-patcher 2.6.0 / com.locket.Locket (API 26)

package io.github.ryuuseiakira.locket.patches.locket.gms

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.InstructionLocation.MatchAfterImmediately
import app.morphe.patcher.StringComparisonType
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.methodCall
import app.morphe.patcher.opcode
import app.morphe.patcher.patch.InstallerType
import app.morphe.patcher.patch.PatchAvailability
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.packageMetadata
import app.morphe.patcher.patch.patch
import app.morphe.patcher.patch.replaceStrings
import app.morphe.patcher.patch.resourceXml
import app.morphe.patcher.string
import app.morphe.patcher.util.returnEarly
import app.morphe.patcher.xml.XmlElement
import app.morphe.patches.all.misc.gms.gmsCorePackageQueriesPatch
import app.morphe.patches.all.misc.fix.spoofsignature.spoofSignaturePatch
import app.morphe.util.getEndEntityCertificate
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import io.github.ryuuseiakira.locket.patches.shared.Constants.COMPATIBILITY_LOCKET
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale

internal const val MICROG_VENDOR_GROUP_ID = "app.revanced"
internal const val MICROG_PACKAGE_NAME = "$MICROG_VENDOR_GROUP_ID.android.gms"

private const val META_SPOOFED_PACKAGE_NAME = "$MICROG_PACKAGE_NAME.SPOOFED_PACKAGE_NAME"
private const val META_SPOOFED_PACKAGE_SIGNATURE = "$MICROG_PACKAGE_NAME.SPOOFED_PACKAGE_SIGNATURE"
private const val META_MICROG_PACKAGE_NAME = "app.revanced.MICROG_PACKAGE_NAME"

private const val GOOGLE_GMS_PACKAGE = "com.google.android.gms"
private const val GOOGLE_PLAY_SERVICES_UTIL_TAG = "GooglePlayServicesUtil"
private const val INVALID_SIGNATURE_MSG = " requires Google Play services, but their signature is invalid."
private const val SERVICE_NOT_AVAILABLE_MSG = "Google Play Services not available"

/**
 * `GooglePlayServicesUtilLight.isGooglePlayServicesAvailable(Context, int)I`.
 * Matched via Play Services tag + invalid signature diagnostic string so R8 splitting
 * `MetadataValueReader` into a separate class does not break the match.
 */
internal val googlePlayUtilityFingerprint = Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
    returnType = "I",
    parameters = listOf("L", "I"),
    filters = listOf(
        string(GOOGLE_PLAY_SERVICES_UTIL_TAG),
        string(GOOGLE_GMS_PACKAGE),
        string(INVALID_SIGNATURE_MSG),
    ),
)

/**
 * `GooglePlayServicesUtilLight.ensurePlayServicesAvailable(Context, int)V`.
 */
internal val serviceCheckFingerprint = Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
    returnType = "V",
    parameters = listOf("L", "I"),
    strings = listOf(SERVICE_NOT_AVAILABLE_MSG),
)

/**
 * `UidVerifier.isGooglePlayServicesUid(Context, int)Z`.
 * Keeps `AppOpsManager` UID package ownership validation intact while bypassing only
 * `GoogleSignatureVerifier.isGooglePublicSignedPackage(PackageInfo)Z`.
 */
internal val uidVerifierFingerprint = Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
    returnType = "Z",
    parameters = listOf("L", "I"),
    filters = listOf(
        string(GOOGLE_GMS_PACKAGE),
        methodCall(
            opcode = Opcode.INVOKE_VIRTUAL,
            parameters = listOf("Landroid/content/pm/PackageInfo;"),
            returnType = "Z",
        ),
        opcode(Opcode.MOVE_RESULT, location = MatchAfterImmediately()),
        opcode(Opcode.RETURN, location = MatchAfterImmediately()),
        string("UidVerifier"),
    ),
)

internal object GmsCoreConstants {
    val PERMISSIONS = setOf(
        "com.google.android.c2dm.permission.RECEIVE",
        "com.google.android.c2dm.permission.SEND",
        "com.google.android.gms.auth.api.phone.permission.SEND",
        "com.google.android.gms.permission.AD_ID",
        "com.google.android.gms.permission.AD_ID_NOTIFICATION",
        "com.google.android.gms.permission.CAR_FUEL",
        "com.google.android.gms.permission.CAR_INFORMATION",
        "com.google.android.gms.permission.CAR_MILEAGE",
        "com.google.android.gms.permission.CAR_SPEED",
        "com.google.android.gms.permission.CAR_VENDOR_EXTENSION",
        "com.google.android.googleapps.permission.GOOGLE_AUTH",
        "com.google.android.googleapps.permission.GOOGLE_AUTH.cp",
        "com.google.android.googleapps.permission.GOOGLE_AUTH.local",
        "com.google.android.googleapps.permission.GOOGLE_AUTH.mail",
        "com.google.android.googleapps.permission.GOOGLE_AUTH.writely",
        "com.google.android.gtalkservice.permission.GTALK_SERVICE",
        "com.google.android.providers.gsf.permission.READ_GSERVICES",
    )

    val ACTIONS = setOf(
        "com.google.android.c2dm.intent.RECEIVE",
        "com.google.android.c2dm.intent.REGISTER",
        "com.google.android.c2dm.intent.REGISTRATION",
        "com.google.android.c2dm.intent.UNREGISTER",
        "com.google.android.contextmanager.service.ContextManagerService.START",
        "com.google.android.gcm.intent.SEND",
        "com.google.android.gms.accounts.ACCOUNT_SERVICE",
        "com.google.android.gms.accountsettings.ACCOUNT_PREFERENCES_SETTINGS",
        "com.google.android.gms.accountsettings.action.BROWSE_SETTINGS",
        "com.google.android.gms.accountsettings.action.VIEW_SETTINGS",
        "com.google.android.gms.accountsettings.MY_ACCOUNT",
        "com.google.android.gms.accountsettings.PRIVACY_SETTINGS",
        "com.google.android.gms.accountsettings.SECURITY_SETTINGS",
        "com.google.android.gms.ads.gservice.START",
        "com.google.android.gms.ads.identifier.service.EVENT_ATTESTATION",
        "com.google.android.gms.ads.service.CACHE",
        "com.google.android.gms.ads.service.CONSENT_LOOKUP",
        "com.google.android.gms.ads.service.HTTP",
        "com.google.android.gms.analytics.service.START",
        "com.google.android.gms.appstate.service.START",
        "com.google.android.gms.appusage.service.START",
        "com.google.android.gms.asterism.service.START",
        "com.google.android.gms.audiomodem.service.AudioModemService.START",
        "com.google.android.gms.audit.service.START",
        "com.google.android.gms.auth.GOOGLE_SIGN_IN",
        "com.google.android.gms.auth.account.authapi.START",
        "com.google.android.gms.auth.account.authenticator.auto.service.START",
        "com.google.android.gms.auth.account.authenticator.chromeos.START",
        "com.google.android.gms.auth.account.authenticator.tv.service.START",
        "com.google.android.gms.auth.account.data.service.START",
        "com.google.android.gms.auth.api.credentials.ASSISTED_SIGNIN",
        "com.google.android.gms.auth.api.credentials.PICKER",
        "com.google.android.gms.auth.api.credentials.service.START",
        "com.google.android.gms.auth.api.identity.service.authorization.START",
        "com.google.android.gms.auth.api.identity.service.credentialsaving.START",
        "com.google.android.gms.auth.api.identity.service.signin.START",
        "com.google.android.gms.auth.api.phone.service.InternalService.START",
        "com.google.android.gms.auth.api.signin.service.START",
        "com.google.android.gms.auth.be.appcert.AppCertService",
        "com.google.android.gms.auth.blockstore.service.START",
        "com.google.android.gms.auth.config.service.START",
        "com.google.android.gms.auth.cryptauth.cryptauthservice.START",
        "com.google.android.gms.auth.login.LOGIN",
        "com.google.android.gms.auth.proximity.devicesyncservice.START",
        "com.google.android.gms.auth.proximity.securechannelservice.START",
        "com.google.android.gms.auth.proximity.START",
        "com.google.android.gms.auth.service.START",
        "com.google.android.gms.backup.ACTION_BACKUP_SETTINGS",
        "com.google.android.gms.backup.G1_BACKUP",
        "com.google.android.gms.backup.G1_RESTORE",
        "com.google.android.gms.backup.GMS_MODULE_RESTORE",
        "com.google.android.gms.beacon.internal.IBleService.START",
        "com.google.android.gms.car.service.START",
        "com.google.android.gms.carrierauth.service.START",
        "com.google.android.gms.cast.firstparty.START",
        "com.google.android.gms.cast.remote_display.service.START",
        "com.google.android.gms.cast.service.BIND_CAST_DEVICE_CONTROLLER_SERVICE",
        "com.google.android.gms.cast_mirroring.service.START",
        "com.google.android.gms.checkin.BIND_TO_SERVICE",
        "com.google.android.gms.chromesync.service.START",
        "com.google.android.gms.clearcut.service.START",
        "com.google.android.gms.common.account.CHOOSE_ACCOUNT",
        "com.google.android.gms.common.download.START",
        "com.google.android.gms.common.service.START",
        "com.google.android.gms.common.telemetry.service.START",
        "com.google.android.gms.config.START",
        "com.google.android.gms.constellation.service.START",
        "com.google.android.gms.credential.manager.service.firstparty.START",
        "com.google.android.gms.deviceconnection.service.START",
        "com.google.android.gms.drive.ApiService.RESET_AFTER_BOOT",
        "com.google.android.gms.drive.ApiService.START",
        "com.google.android.gms.drive.ApiService.STOP",
        "com.google.android.gms.droidguard.service.INIT",
        "com.google.android.gms.droidguard.service.PING",
        "com.google.android.gms.droidguard.service.START",
        "com.google.android.gms.enterprise.loader.service.START",
        "com.google.android.gms.facs.cache.service.START",
        "com.google.android.gms.facs.internal.service.START",
        "com.google.android.gms.feedback.internal.IFeedbackService",
        "com.google.android.gms.fido.credentialstore.internal_service.START",
        "com.google.android.gms.fido.fido2.privileged.START",
        "com.google.android.gms.fido.fido2.regular.START",
        "com.google.android.gms.fido.fido2.zeroparty.START",
        "com.google.android.gms.fido.sourcedevice.service.START",
        "com.google.android.gms.fido.targetdevice.internal_service.START",
        "com.google.android.gms.fido.u2f.privileged.START",
        "com.google.android.gms.fido.u2f.thirdparty.START",
        "com.google.android.gms.fido.u2f.zeroparty.START",
        "com.google.android.gms.fitness.BleApi",
        "com.google.android.gms.fitness.ConfigApi",
        "com.google.android.gms.fitness.GoalsApi",
        "com.google.android.gms.fitness.GoogleFitnessService.START",
        "com.google.android.gms.fitness.HistoryApi",
        "com.google.android.gms.fitness.InternalApi",
        "com.google.android.gms.fitness.RecordingApi",
        "com.google.android.gms.fitness.SensorsApi",
        "com.google.android.gms.fitness.SessionsApi",
        "com.google.android.gms.fonts.service.START",
        "com.google.android.gms.freighter.service.START",
        "com.google.android.gms.games.internal.connect.service.START",
        "com.google.android.gms.games.PLAY_GAMES_UPGRADE",
        "com.google.android.gms.games.service.START",
        "com.google.android.gms.gass.START",
        "com.google.android.gms.gmscompliance.service.START",
        "com.google.android.gms.googlehelp.HELP",
        "com.google.android.gms.googlehelp.service.GoogleHelpService.START",
        "com.google.android.gms.growth.service.START",
        "com.google.android.gms.herrevad.services.LightweightNetworkQualityAndroidService.START",
        "com.google.android.gms.icing.INDEX_SERVICE",
        "com.google.android.gms.icing.LIGHTWEIGHT_INDEX_SERVICE",
        "com.google.android.gms.identity.service.BIND",
        "com.google.android.gms.inappreach.service.START",
        "com.google.android.gms.instantapps.START",
        "com.google.android.gms.kids.service.START",
        "com.google.android.gms.languageprofile.service.START",
        "com.google.android.gms.learning.internal.dynamitesupport.START",
        "com.google.android.gms.learning.intservice.START",
        "com.google.android.gms.learning.predictor.START",
        "com.google.android.gms.learning.trainer.START",
        "com.google.android.gms.learning.training.background.START",
        "com.google.android.gms.location.places.GeoDataApi",
        "com.google.android.gms.location.places.PlaceDetectionApi",
        "com.google.android.gms.location.places.PlacesApi",
        "com.google.android.gms.location.places.ui.PICK_PLACE",
        "com.google.android.gms.location.reporting.service.START",
        "com.google.android.gms.location.settings.LOCATION_HISTORY",
        "com.google.android.gms.location.settings.LOCATION_REPORTING_SETTINGS",
        "com.google.android.gms.locationsharing.api.START",
        "com.google.android.gms.locationsharingreporter.service.START",
        "com.google.android.gms.lockbox.service.START",
        "com.google.android.gms.matchstick.lighter.service.START",
        "com.google.android.gms.mdm.services.DeviceManagerApiService.START",
        "com.google.android.gms.mdm.services.START",
        "com.google.android.gms.mdns.service.START",
        "com.google.android.gms.measurement.START",
        "com.google.android.gms.nearby.bootstrap.service.NearbyBootstrapService.START",
        "com.google.android.gms.nearby.connection.service.START",
        "com.google.android.gms.nearby.fastpair.START",
        "com.google.android.gms.nearby.messages.service.NearbyMessagesService.START",
        "com.google.android.gms.nearby.sharing.service.NearbySharingService.START",
        "com.google.android.gms.nearby.sharing.START_SERVICE",
        "com.google.android.gms.notifications.service.START",
        "com.google.android.gms.ocr.service.internal.START",
        "com.google.android.gms.ocr.service.START",
        "com.google.android.gms.oss.licenses.service.START",
        "com.google.android.gms.payse.service.BIND",
        "com.google.android.gms.people.contactssync.service.START",
        "com.google.android.gms.people.service.START",
        "com.google.android.gms.phenotype.service.START",
        "com.google.android.gms.photos.autobackup.service.START",
        "com.google.android.gms.playlog.service.START",
        "com.google.android.gms.plus.service.default.INTENT",
        "com.google.android.gms.plus.service.image.INTENT",
        "com.google.android.gms.plus.service.internal.START",
        "com.google.android.gms.plus.service.START",
        "com.google.android.gms.potokens.service.START",
        "com.google.android.gms.pseudonymous.service.START",
        "com.google.android.gms.rcs.START",
        "com.google.android.gms.reminders.service.START",
        "com.google.android.gms.romanesco.MODULE_BACKUP_AGENT",
        "com.google.android.gms.romanesco.service.START",
        "com.google.android.gms.safetynet.service.START",
        "com.google.android.gms.scheduler.ACTION_PROXY_SCHEDULE",
        "com.google.android.gms.search.service.SEARCH_AUTH_START",
        "com.google.android.gms.semanticlocation.service.START_ODLH",
        "com.google.android.gms.sesame.service.BIND",
        "com.google.android.gms.settings.EXPOSURE_NOTIFICATION_SETTINGS",
        "com.google.android.gms.setup.auth.SecondDeviceAuth.START",
        "com.google.android.gms.signin.service.START",
        "com.google.android.gms.smartdevice.d2d.SourceDeviceService.START",
        "com.google.android.gms.smartdevice.d2d.TargetDeviceService.START",
        "com.google.android.gms.smartdevice.directtransfer.SourceDirectTransferService.START",
        "com.google.android.gms.smartdevice.directtransfer.TargetDirectTransferService.START",
        "com.google.android.gms.smartdevice.postsetup.PostSetupService.START",
        "com.google.android.gms.smartdevice.setup.accounts.AccountsService.START",
        "com.google.android.gms.smartdevice.wifi.START_WIFI_HELPER_SERVICE",
        "com.google.android.gms.social.location.activity.service.START",
        "com.google.android.gms.speech.service.START",
        "com.google.android.gms.statementservice.EXECUTE",
        "com.google.android.gms.stats.ACTION_UPLOAD_DROPBOX_ENTRIES",
        "com.google.android.gms.tapandpay.service.BIND",
        "com.google.android.gms.telephonyspam.service.START",
        "com.google.android.gms.testsupport.service.START",
        "com.google.android.gms.thunderbird.service.START",
        "com.google.android.gms.trustagent.BridgeApi.START",
        "com.google.android.gms.trustagent.StateApi.START",
        "com.google.android.gms.trustagent.trustlet.trustletmanagerservice.BIND",
        "com.google.android.gms.trustlet.bluetooth.service.BIND",
        "com.google.android.gms.trustlet.connectionlessble.service.BIND",
        "com.google.android.gms.trustlet.face.service.BIND",
        "com.google.android.gms.trustlet.nfc.service.BIND",
        "com.google.android.gms.trustlet.onbody.service.BIND",
        "com.google.android.gms.trustlet.place.service.BIND",
        "com.google.android.gms.trustlet.voiceunlock.service.BIND",
        "com.google.android.gms.udc.service.START",
        "com.google.android.gms.update.START_API_SERVICE",
        "com.google.android.gms.update.START_SERVICE",
        "com.google.android.gms.update.START_SINGLE_USER_API_SERVICE",
        "com.google.android.gms.update.START_TV_API_SERVICE",
        "com.google.android.gms.usagereporting.service.START",
        "com.google.android.gms.userlocation.service.START",
        "com.google.android.gms.vehicle.cabin.service.START",
        "com.google.android.gms.vehicle.climate.service.START",
        "com.google.android.gms.vehicle.info.service.START",
        "com.google.android.gms.wallet.firstparty.ACTION_PURCHASE_MANAGER",
        "com.google.android.gms.wallet.service.BIND",
        "com.google.android.gms.walletp2p.service.firstparty.BIND",
        "com.google.android.gms.walletp2p.service.zeroparty.BIND",
        "com.google.android.gms.wearable.BIND",
        "com.google.android.gms.wearable.BIND_LISTENER",
        "com.google.android.gms.wearable.DATA_CHANGED",
        "com.google.android.gms.wearable.MESSAGE_RECEIVED",
        "com.google.android.gms.wearable.NODE_CHANGED",
        "com.google.android.gms.wearable.TOS",
        "com.google.android.gsf.action.GET_GLS",
        "com.google.android.location.internal.GoogleLocationManagerService",
        "com.google.android.location.internal.GoogleLocationManagerService.START",
        "com.google.android.location.settings.LOCATION_REPORTING_SETTINGS",
        "com.google.android.mdd.service.START",
        "com.google.android.mdh.service.listener.START",
        "com.google.android.mdh.service.START",
        "com.google.android.mobstore.service.START",
        "com.google.iid.TOKEN_REQUEST",
    )

    val AUTHORITIES = setOf(
        "com.google.android.gms.auth.accounts",
        "com.google.android.gms.chimera",
        "com.google.android.gms.fileprovider",
        "com.google.android.gms.fonts",
        "com.google.android.gms.phenotype",
        "com.google.android.gsf.gservices",
        "com.google.android.gsf.subscribedfeeds",
        "com.google.settings",
    )

    val EXACT_REPLACEMENTS: List<Pair<String, String>> = linkedMapOf<String, String>().apply {
        put("com.google", MICROG_VENDOR_GROUP_ID)
        put(GOOGLE_GMS_PACKAGE, MICROG_PACKAGE_NAME)
        for (item in PERMISSIONS + ACTIONS + AUTHORITIES) {
            put(item, item.replace("com.google", MICROG_VENDOR_GROUP_ID))
        }
    }.entries.map { it.key to it.value }

    private val AUTHORITY_URI_PREFIXES = AUTHORITIES.map { authority ->
        "content://$authority" to "content://${authority.replace("com.google", MICROG_VENDOR_GROUP_ID)}"
    }

    val MANIFEST_REPLACEMENTS: Map<String, String> = mapOf(
        "com.google.android.c2dm" to "$MICROG_VENDOR_GROUP_ID.android.c2dm",
        "com.google.android.gms.permission.AD_ID" to "$MICROG_VENDOR_GROUP_ID.android.gms.permission.AD_ID",
        "com.google.android.providers.gsf.permission.READ_GSERVICES" to
            "$MICROG_VENDOR_GROUP_ID.android.providers.gsf.permission.READ_GSERVICES",
    )

    internal fun transformContentUri(value: String): String? {
        for ((fromPrefix, toPrefix) in AUTHORITY_URI_PREFIXES) {
            if (value == fromPrefix || value.startsWith("$fromPrefix/")) {
                return toPrefix + value.removePrefix(fromPrefix)
            }
        }
        return null
    }
}

internal fun certificateSha1Hex(certificate: X509Certificate): String {
    val digest = MessageDigest.getInstance("SHA-1").digest(certificate.encoded)
    return digest.joinToString("") { byte ->
        "%02x".format(Locale.ROOT, byte.toInt() and 0xff)
    }
}

internal fun rewriteManifestAttributes(element: XmlElement) {
    for (attrName in element.attributeNames) {
        val original = element.attribute(attrName) ?: continue
        var updated = original
        for ((from, to) in GmsCoreConstants.MANIFEST_REPLACEMENTS) {
            updated = updated.replace(from, to)
        }
        if (updated != original) {
            element.setAttribute(attrName, updated)
        }
    }
}

private fun XmlElement.setOrAppendMetaData(name: String, value: String) {
    val existing = children("meta-data").firstOrNull { it.attribute("android:name") == name }
    if (existing != null) {
        existing.setAttribute("android:value", value)
        return
    }
    appendChild("meta-data") {
        setAttribute("android:name", name)
        setAttribute("android:value", value)
    }
}

/**
 * Redirects Play Services SDK calls and Cloud Messaging intents from `com.google.android.gms`
 * to MicroG-RE (`app.revanced.android.gms`) while spoofing Locket's original package identity
 * and bypassing Play Services APK/UID signature verification checks.
 */
@Suppress("unused")
val gmsCoreSupportPatch = patch(
    name = "GmsCore support",
    description = "Enables Google Sign-In and Play Services features without root using MicroG-RE (app.revanced.android.gms).",
    default = true,
) {
    compatibleWith(COMPATIBILITY_LOCKET)

    availability { installer, _ ->
        when (installer) {
            InstallerType.MOUNT -> PatchAvailability.UNAVAILABLE
            InstallerType.STANDARD, InstallerType.SHIZUKU -> PatchAvailability.ENABLED
        }
    }

    dependsOn(
        gmsCorePackageQueriesPatch,
        spoofSignaturePatch,
    )

    execute {
        // Match and patch signature/availability gates before replacing "com.google.android.gms" strings.
        val utilityMethod = googlePlayUtilityFingerprint.methodOrNull
            ?: throw PatchException("Could not resolve GooglePlayServicesUtilLight.isGooglePlayServicesAvailable.")
        utilityMethod.returnEarly(0)

        serviceCheckFingerprint.methodOrNull?.returnEarly()

        uidVerifierFingerprint.let { fp ->
            val moveResultMatch = fp.instructionMatchesOrNull?.getOrNull(2)
                ?: throw PatchException("Could not resolve UidVerifier.isGooglePlayServicesUid move-result.")
            val reg = (moveResultMatch.instruction as OneRegisterInstruction).registerA
            val loadTrue = if (reg < 16) "const/4 v$reg, 0x1" else "const/16 v$reg, 0x1"
            fp.method.replaceInstruction(moveResultMatch.index, loadTrue)
        }

        replaceStrings(
            GmsCoreConstants.EXACT_REPLACEMENTS.map { (fromString, toString) ->
                string(fromString) to toString
            },
        )
        replaceStrings(string("content://", StringComparisonType.STARTS_WITH)) { _, _, value ->
            GmsCoreConstants.transformContentUri(value)
        }

        val endEntityCert = getEndEntityCertificate(packageMetadata.signingCertificates)
        val originalSignatureSha1 = certificateSha1Hex(endEntityCert)
        val originalPackageName = packageMetadata.packageName

        resourceXml("AndroidManifest.xml").use { manifest ->
            manifest.elements().forEach(::rewriteManifestAttributes)

            val application = manifest.elements("application").firstOrNull()
                ?: throw PatchException("AndroidManifest.xml does not contain an <application> element.")
            application.setOrAppendMetaData(META_SPOOFED_PACKAGE_NAME, originalPackageName)
            application.setOrAppendMetaData(META_SPOOFED_PACKAGE_SIGNATURE, originalSignatureSha1)
            application.setOrAppendMetaData(META_MICROG_PACKAGE_NAME, MICROG_PACKAGE_NAME)
        }
    }
}
