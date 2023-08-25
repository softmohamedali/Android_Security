package com.moali.android_security.security

import android.content.Context
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

//you need add androidx security dependency
class EncryptedSharedPreferences (
    private val context: Context
){
    //we use master key from android x jetpack for encrypt file or shared preference
    val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
    val masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)


    // Release Candidate Option
    val sharedPreferences = EncryptedSharedPreferences.create(
        "FileName",
        masterKeyAlias,
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun write(key:String,value:String){
        sharedPreferences.edit{
            putString(key,value)
        }
    }
}
