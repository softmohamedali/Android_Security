package com.moali.android_security.security

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import java.io.File

class EncryptedSecureFile (
    private val context: Context
){

    //we use master key from android x jetpack for encrypt file or shared preference
    private val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
    private val masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)

    private val encryptedFile = EncryptedFile.Builder(
        File("directoryPath", "FileName"),
        context,
        masterKeyAlias,
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
    ).build()

    fun writeToFile(data:String){
        encryptedFile.openFileOutput().bufferedWriter().use {
            it.write(data)
        }
    }

    fun readFile():String{
        return encryptedFile.openFileInput().read()
            .toString()
    }





}