package app.tauri.p256

import android.app.Activity
import androidx.credentials.*
import app.tauri.Logger
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers.IO
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

@InvokeArg
class CreateCredentialRequestParams {
    lateinit var creationParams: String
}

@InvokeArg
class GetCredentialRequestParams {
    lateinit var getParams: String
}

data class PubKeyResponse(val pubKeyJson: String)

@TauriPlugin
class P256SignerPlugin(private val activity: Activity): Plugin(activity) {

    private val credentialManager = CredentialManager.create(activity)
    private val scope = CoroutineScope(IO + SupervisorJob())
    private var isRequesting = false;

    @Command
    fun create_credential(invoke: Invoke) {
        // todo: error handling and try catch / check for google services
        val invokeParams = invoke.parseArgs(CreateCredentialRequestParams::class.java)
        if (isRequesting) return
        isRequesting = true
        scope.launch {
            val request = CreatePublicKeyCredentialRequest(invokeParams.creationParams)
            val response = credentialManager.createCredential(activity, request)
            val pubkeyResponse = response as? CreatePublicKeyCredentialResponse
            invoke.resolveObject(PubKeyResponse(pubkeyResponse!!.registrationResponseJson))
            isRequesting = false
        }
    }

    @Command
    fun get_credential(invoke: Invoke) {
        // todo: error handling and try catch / check for google services
        val invokeParams = invoke.parseArgs(GetCredentialRequestParams::class.java)
        if (isRequesting) return
        isRequesting = true
        scope.launch {
            val credentialRequest = GetPublicKeyCredentialOption(invokeParams.getParams)
            val request = GetCredentialRequest(listOf(credentialRequest))
            val response = credentialManager.getCredential(activity, request)
            val pubKeyCred = response.credential as PublicKeyCredential
            invoke.resolveObject(PubKeyResponse(pubKeyCred.authenticationResponseJson))
            isRequesting = false
        }
    }

}
