package com.moali.android_security.security

import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import javax.security.auth.x500.X500Principal

class RSACryptography {
    companion object{
        const val KEYPAIR_ALIAS="keyPairSecret"
    }

    private val startDate = GregorianCalendar()
    private val endDate = GregorianCalendar()


    private val keystore= KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun createScretKeyPair(): KeyPair {
        endDate.add(Calendar.YEAR, 1)
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator
            .getInstance(KeyProperties.KEY_ALGORITHM_RSA)
            .apply {
                val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(KEYPAIR_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
                    setCertificateSerialNumber(BigInteger.valueOf(777))
                    setCertificateSubject(X500Principal("CN=$KEYPAIR_ALIAS"))
                    setDigests(KeyProperties.DIGEST_SHA256)
                    setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    setCertificateNotBefore(startDate.time)
                    setCertificateNotAfter(endDate.time)
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationValidityDurationSeconds(30)
                    build()
                }
                initialize(parameterSpec)
            }

        return keyPairGenerator.genKeyPair()
    }

    private fun signData(bytes:ByteArray) :String?{

        try {
            val privateKey: PrivateKey = keystore.getKey(KEYPAIR_ALIAS, null) as PrivateKey

            val signature: ByteArray? = Signature.getInstance("SHA256withRSA").run {
                initSign(privateKey)
                update(bytes)
                sign()
            }
            if (signature != null) {
                 return Base64.encodeToString(signature, Base64.DEFAULT)
            }

        } catch (e: UserNotAuthenticatedException) {
            //Exception thrown when the user has not been authenticated
            //if you dont need authenticate just in create secret pair key set
            //setUserAuthenticationRequired(true) to false
        } catch (e: KeyPermanentlyInvalidatedException) {
            //Exception thrown when the key has been invalidated for example when lock screen has been disabled.
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
        return null
    }


    private fun verifyData(data: String,signature: String, publicKey: PublicKey):Boolean {
        val certificate: Certificate? = keystore.getCertificate(KEYPAIR_ALIAS)
        if (certificate != null) {
            val signatureByte=Base64.decode(signature, Base64.DEFAULT)
            val isValid: Boolean = Signature.getInstance("SHA256withRSA").run {
                initVerify(certificate)
                update(data.toByteArray())
                verify(signatureByte)
            }
            return isValid
        }
        return false
    }

}