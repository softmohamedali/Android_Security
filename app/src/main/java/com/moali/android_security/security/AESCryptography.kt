package com.moali.android_security.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.KeyStore.SecretKeyEntry
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class AESCryptography {

    companion object{
        val MODE=KeyProperties.BLOCK_MODE_CBC
        val ALGORITHM=KeyProperties.KEY_ALGORITHM_AES
        val PADDING=KeyProperties.ENCRYPTION_PADDING_PKCS7
        val TRANSFORMATION="$ALGORITHM/$MODE/$PADDING"
    }

    private val keystore=KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun getKeySecret():SecretKey{
        val existingKey=keystore.getEntry("secretKey",null) as? SecretKeyEntry
        return existingKey?.secretKey ?:createKeySecret()
    }

    private fun createKeySecret():SecretKey{
        return KeyGenerator.getInstance(ALGORITHM).apply {
            init(
                KeyGenParameterSpec.Builder("secretKey",
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(MODE)
                    .setEncryptionPaddings(PADDING)
                    .setUserAuthenticationRequired(false)//if you use bio
                    .setRandomizedEncryptionRequired(false)
                    .build()
            )
        }.generateKey()
    }

    private val encryptedCipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE,getKeySecret())
    }

    //iv refferd to Intilization vector
    fun getDecryptedCipherForIV(iv:ByteArray):Cipher{
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE,getKeySecret(),IvParameterSpec(iv))
        }
    }

    /*
    this fun will take byte you want to encrypt =>bytes
    and take stream you want to write encrypted byte inside it =>stream
    and finally return cipher byte or byte which encrypted
     */
    fun encrypt(bytes:ByteArray,stream:OutputStream):ByteArray{
        val cipherByte=encryptedCipher.doFinal(bytes)
        stream.use {
            it.write(encryptedCipher.iv.size)
            it.write(encryptedCipher.iv)
            it.write(cipherByte.size)
            it.write(cipherByte)
        }
        return cipherByte
    }

    fun decrypt(stream: InputStream):ByteArray{
        return stream.use {
            val ivSize=it.read()
            val iv=ByteArray(ivSize)
            it.read(iv)
            val cipherByteSize=it.read()
            val cipherByte=ByteArray(cipherByteSize)
            it.read(cipherByte)
            getDecryptedCipherForIV(iv).doFinal(cipherByte)
        }
    }




}