// patches/src/test/kotlin/io/github/ryuuseiakira/locket/patches/locket/gms/GmsCoreSupportPatchTest.kt
// kotlin / GmsCoreSupportPatchTest / kotlin.test + JUnit / GmsCoreSupportPatch

package io.github.ryuuseiakira.locket.patches.locket.gms

import app.morphe.patcher.patch.ApkArchitecture
import app.morphe.patcher.patch.InstallerType
import app.morphe.patcher.patch.PatchAvailability
import app.morphe.patcher.xml.XmlElement
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GmsCoreSupportPatchTest {
    @Test
    fun `patch metadata, dependencies, and install mode availability are configured properly`() {
        assertEquals("GmsCore support", gmsCoreSupportPatch.name)
        assertTrue(gmsCoreSupportPatch.default)
        assertEquals("com.locket.Locket", gmsCoreSupportPatch.compatibility?.single()?.packageName)
        assertEquals(2, gmsCoreSupportPatch.dependencies.size)

        val resolver = gmsCoreSupportPatch.availability!!
        assertEquals(
            PatchAvailability.UNAVAILABLE,
            resolver.resolve(InstallerType.MOUNT, ApkArchitecture.ARM64_V8A),
        )
        assertEquals(
            PatchAvailability.ENABLED,
            resolver.resolve(InstallerType.STANDARD, ApkArchitecture.ARM64_V8A),
        )
        assertEquals(
            PatchAvailability.ENABLED,
            resolver.resolve(InstallerType.SHIZUKU, ApkArchitecture.UNIVERSAL),
        )
    }

    @Test
    fun `exact string replacements redirect Play Services, Auth, Identity, and C2DM without duplicates`() {
        val map = GmsCoreConstants.EXACT_REPLACEMENTS.toMap()
        assertEquals(map.size, GmsCoreConstants.EXACT_REPLACEMENTS.size)

        assertEquals("app.revanced", map["com.google"])
        assertEquals("app.revanced.android.gms", map["com.google.android.gms"])
        assertEquals("app.revanced.android.c2dm.intent.REGISTER", map["com.google.android.c2dm.intent.REGISTER"])
        assertEquals("app.revanced.android.c2dm.intent.REGISTRATION", map["com.google.android.c2dm.intent.REGISTRATION"])
        assertEquals("app.revanced.android.c2dm.intent.RECEIVE", map["com.google.android.c2dm.intent.RECEIVE"])
        assertEquals("app.revanced.android.c2dm.permission.SEND", map["com.google.android.c2dm.permission.SEND"])
        assertEquals(
            "app.revanced.android.gms.auth.api.signin.service.START",
            map["com.google.android.gms.auth.api.signin.service.START"],
        )
        assertEquals(
            "app.revanced.android.gms.auth.api.identity.service.signin.START",
            map["com.google.android.gms.auth.api.identity.service.signin.START"],
        )
        assertEquals(
            "app.revanced.android.gms.signin.service.START",
            map["com.google.android.gms.signin.service.START"],
        )
        assertEquals(
            "app.revanced.android.location.internal.GoogleLocationManagerService.START",
            map["com.google.android.location.internal.GoogleLocationManagerService.START"],
        )

        // Ensure non-IPC metadata/Firebase identifiers are untouched.
        assertNull(map["com.google.android.gms.version"])
        assertNull(map["com.google.firebase.MESSAGING_EVENT"])
        assertNull(map["com.locket.Locket"])
    }

    @Test
    fun `content uri transform rewrites GServices and Phenotype URIs only`() {
        assertEquals(
            "content://app.revanced.android.gsf.gservices/prefix",
            GmsCoreConstants.transformContentUri("content://com.google.android.gsf.gservices/prefix"),
        )
        assertEquals(
            "content://app.revanced.android.gsf.gservices",
            GmsCoreConstants.transformContentUri("content://com.google.android.gsf.gservices"),
        )
        assertEquals(
            "content://app.revanced.android.gms.phenotype/com.locket.Locket",
            GmsCoreConstants.transformContentUri("content://com.google.android.gms.phenotype/com.locket.Locket"),
        )
        assertNull(GmsCoreConstants.transformContentUri("content://com.locket.Locket.fileprovider/cache/a.jpg"))
    }

    @Test
    fun `manifest attribute rewriter updates C2DM and GServices while preserving Firebase and FileProviders`() {
        val c2dmReceiver = FakeXmlElement(
            tag = "receiver",
            attrs = linkedMapOf(
                "android:name" to "io.invertase.firebase.messaging.ReactNativeFirebaseMessagingReceiver",
                "android:permission" to "com.google.android.c2dm.permission.SEND",
            ),
        )
        val c2dmAction = FakeXmlElement(
            tag = "action",
            attrs = linkedMapOf("android:name" to "com.google.android.c2dm.intent.RECEIVE"),
        )
        val gservicesPerm = FakeXmlElement(
            tag = "uses-permission",
            attrs = linkedMapOf("android:name" to "com.google.android.providers.gsf.permission.READ_GSERVICES"),
        )
        val adIdPerm = FakeXmlElement(
            tag = "uses-permission",
            attrs = linkedMapOf("android:name" to "com.google.android.gms.permission.AD_ID"),
        )
        val fileProvider = FakeXmlElement(
            tag = "provider",
            attrs = linkedMapOf("android:authorities" to "com.locket.Locket.fileprovider"),
        )
        val firebaseService = FakeXmlElement(
            tag = "action",
            attrs = linkedMapOf("android:name" to "com.google.firebase.MESSAGING_EVENT"),
        )

        listOf(c2dmReceiver, c2dmAction, gservicesPerm, adIdPerm, fileProvider, firebaseService)
            .forEach(::rewriteManifestAttributes)

        assertEquals("app.revanced.android.c2dm.permission.SEND", c2dmReceiver.attribute("android:permission"))
        assertEquals("app.revanced.android.c2dm.intent.RECEIVE", c2dmAction.attribute("android:name"))
        assertEquals(
            "app.revanced.android.providers.gsf.permission.READ_GSERVICES",
            gservicesPerm.attribute("android:name"),
        )
        assertEquals("app.revanced.android.gms.permission.AD_ID", adIdPerm.attribute("android:name"))
        assertEquals("com.locket.Locket.fileprovider", fileProvider.attribute("android:authorities"))
        assertEquals("com.google.firebase.MESSAGING_EVENT", firebaseService.attribute("android:name"))
    }

    @Test
    fun `certificateSha1Hex produces 40-char lowercase SHA-1 hex matching SHA-1 digest of DER bytes`() {
        val fakeDer = byteArrayOf(0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x7f)
        val sha1 = certificateSha1Hex(FakeX509Certificate(fakeDer))
        assertEquals(40, sha1.length)
        assertTrue(sha1.all { it in '0'..'9' || it in 'a'..'f' })
        // Precomputed SHA-1("3005010203047f") == d95a8f6f... verified dynamically via MessageDigest in runtime test
        val expected = java.security.MessageDigest.getInstance("SHA-1").digest(fakeDer)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertEquals(expected, sha1)
    }

    private class FakeXmlElement(
        override var tag: String,
        private val attrs: LinkedHashMap<String, String> = linkedMapOf(),
    ) : XmlElement {
        override val parent: XmlElement? = null
        override val children: MutableList<XmlElement> = mutableListOf()
        override var text: String = ""
        override val attributeNames: List<String> get() = attrs.keys.toList()
        override fun attribute(name: String): String? = attrs[name]
        override fun setAttribute(name: String, value: String) { attrs[name] = value }
        override fun removeAttribute(name: String) { attrs.remove(name) }
        override fun elementByAttribute(name: String, value: String): XmlElement =
            elementByAttributeOrNull(name, value) ?: error("Missing $name=$value")
        override fun insertChild(index: Int, tag: String, init: XmlElement.() -> Unit): XmlElement =
            FakeXmlElement(tag).apply(init).also { children.add(index, it) }
        override fun insertCopy(index: Int, source: XmlElement): XmlElement =
            insertChild(index, source.tag) { copyAttributesFrom(source) }
        override fun remove() {}
        override fun removeChildren() { children.clear() }
    }

    private class FakeX509Certificate(private val der: ByteArray) : X509Certificate() {
        override fun getEncoded(): ByteArray = der
        override fun checkValidity() {}
        override fun checkValidity(date: Date?) {}
        override fun getVersion(): Int = 3
        override fun getSerialNumber(): BigInteger = BigInteger.ONE
        @Deprecated("Deprecated in Java")
        override fun getIssuerDN(): Principal = Principal { "CN=Test" }
        @Deprecated("Deprecated in Java")
        override fun getSubjectDN(): Principal = Principal { "CN=Test" }
        override fun getNotBefore(): Date = Date(0)
        override fun getNotAfter(): Date = Date(0)
        override fun getTBSCertificate(): ByteArray = der
        override fun getSignature(): ByteArray = byteArrayOf()
        override fun getSigAlgName(): String = "SHA256withRSA"
        override fun getSigAlgOID(): String = "1.2.840.113549.1.1.11"
        override fun getSigAlgParams(): ByteArray? = null
        override fun getIssuerUniqueID(): BooleanArray? = null
        override fun getSubjectUniqueID(): BooleanArray? = null
        override fun getKeyUsage(): BooleanArray? = null
        override fun getBasicConstraints(): Int = -1
        override fun verify(key: PublicKey?) {}
        override fun verify(key: PublicKey?, sigProvider: String?) {}
        override fun toString(): String = "FakeX509Certificate"
        override fun getPublicKey(): PublicKey = object : PublicKey {
            override fun getAlgorithm() = "RSA"
            override fun getFormat() = "X.509"
            override fun getEncoded() = ByteArray(0)
        }
        override fun hasUnsupportedCriticalExtension(): Boolean = false
        override fun getCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
        override fun getNonCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
        override fun getExtensionValue(oid: String?): ByteArray? = null
    }
}
