package com.aran.vault

import android.app.Activity
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Intent
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.Gravity
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

fun utcNow(pattern: String): String = SimpleDateFormat(pattern, Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date())

// The AES-256 key is generated inside AndroidKeyStore and never leaves it.
class VaultStore(root: File, private val alias: String) {
    private val dir = File(root, alias).apply { mkdirs() }
    private val chainFile = File(dir, "chain.json")

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return generator.generateKey()
    }

    fun chain(): JSONArray = if (chainFile.exists()) JSONArray(chainFile.readText()) else JSONArray()

    fun head(): String = chain().let { if (it.length() == 0) "GENESIS" else it.getJSONObject(it.length() - 1).getString("hash") }

    // True if a captured message with this source text hash is already in the chain (dedup).
    fun hasMessage(msgSha: String): Boolean {
        val chain = chain()
        for (i in 0 until chain.length()) if (chain.getJSONObject(i).optString("msg_sha") == msgSha) return true
        return false
    }

    fun add(type: String, name: String, plain: ByteArray, meta: JSONObject? = null): JSONObject {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val blob = cipher.iv + cipher.doFinal(plain)
        val chain = chain()
        val index = chain.length()
        File(dir, "$index.bin").writeBytes(blob)
        val prev = head()
        val addedAt = utcNow("yyyy-MM-dd'T'HH:mm:ss'Z'")
        val contentSha = sha256Hex(plain)
        val cipherSha = sha256Hex(blob)
        // Must match vault_chain.entry_body on the Desk exactly.
        val body = "$index|$type|$name|$addedAt|$contentSha|$cipherSha|$prev"
        val entry = JSONObject().put("index", index).put("type", type).put("name", name).put("added_at", addedAt)
            .put("content_sha256", contentSha).put("cipher_sha256", cipherSha).put("prev", prev).put("hash", sha256Hex(body.toByteArray()))
        meta?.let { for (k in it.keys()) entry.put(k, it.get(k)) }
        chain.put(entry)
        chainFile.writeText(chain.toString(2))
        return entry
    }

    fun open(index: Int): ByteArray {
        val blob = File(dir, "$index.bin").readBytes()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12))
        return cipher.doFinal(blob, 12, blob.size - 12)
    }

    fun exportPack(): JSONObject = JSONObject().put("source", "aran-vault").put("format", "aran-vault/1")
        .put("exported_at", utcNow("yyyy-MM-dd'T'HH:mm:ss'Z'")).put("items", chain()).put("head", head())
}

class VaultActivity : Activity() {
    private lateinit var store: VaultStore
    private lateinit var list: LinearLayout
    private lateinit var status: TextView
    private val pick = 7

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = BG
        window.navigationBarColor = BG
        store = VaultStore(filesDir, if (intent.getBooleanExtra("decoy", false)) "aran_decoy" else "aran_vault")
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(BG); setPadding(48, 110, 48, 48) }
        root.addView(TextView(this).apply { text = "Vault"; textSize = 32f; setTextColor(Color.WHITE); typeface = Typeface.DEFAULT_BOLD })
        status = TextView(this).apply { textSize = 13f; setTextColor(FN); typeface = Typeface.MONOSPACE; setPadding(0, 8, 0, 28) }
        root.addView(status)
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun action(label: String, color: Int, onClick: () -> Unit) = actions.addView(Button(this).apply {
            text = label; textSize = 15f; setTextColor(Color.WHITE); background = pill(color, 28f); isAllCaps = false; stateListAnimator = null
            setOnClickListener { onClick() }
        }, LinearLayout.LayoutParams(0, 140, 1f).apply { setMargins(0, 0, 16, 0) })
        action("+ Add evidence", OP) {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
                .putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/*", "text/*", "application/zip")), pick)
        }
        action("Export pack", KEY) { export() }
        root.addView(actions)
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 32, 0, 0) }
        root.addView(ScrollView(this).apply { addView(list) }, LinearLayout.LayoutParams(-1, 0, 1f))
        root.addView(TextView(this).apply {
            text = "Encrypted with a hardware key (AES-256-GCM). Each item is linked to the last in a SHA-256 chain. Nothing leaves this phone unless you export."
            textSize = 12f; setTextColor(FN); setPadding(0, 24, 0, 0)
        })
        setContentView(root)
        refresh()
    }

    // Leaving the app locks the vault; reopening shows only the calculator.
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations && !picking) finish()
    }

    private var picking = false

    override fun startActivityForResult(intent: Intent, requestCode: Int) {
        picking = true
        super.startActivityForResult(intent, requestCode)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        picking = false
        val uri = data?.data ?: return
        if (requestCode != pick || resultCode != RESULT_OK) return
        val bytes = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
        val mime = contentResolver.getType(uri) ?: ""
        val type = when { mime.startsWith("image/") -> "screenshot"; mime.startsWith("text/") || mime.contains("zip") -> "chat_export"; else -> "file" }
        val entry = store.add(type, displayName(uri), bytes)
        Toast.makeText(this, "Added #${entry.getInt("index") + 1} to the chain", Toast.LENGTH_SHORT).show()
        refresh()
    }

    private fun displayName(uri: Uri): String = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (it.moveToFirst()) it.getString(0) else null
    }?.replace("|", "_") ?: "item"

    private fun refresh() {
        val chain = store.chain()
        status.text = "${chain.length()} items · chain head ${store.head().take(16)}…"
        list.removeAllViews()
        if (chain.length() == 0) {
            list.addView(TextView(this).apply { text = "Empty. Add screenshots or chat exports."; setTextColor(FN); textSize = 15f; gravity = Gravity.CENTER; setPadding(0, 80, 0, 0) })
        }
        for (i in chain.length() - 1 downTo 0) {
            val entry = chain.getJSONObject(i)
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; background = pill(KEY, 24f); setPadding(36, 28, 36, 28)
                setOnClickListener { show(entry) }
            }
            card.addView(TextView(this).apply {
                text = "#${i + 1}  ${entry.getString("type").replace("_", " ")}  ·  ${entry.getString("added_at").replace("T", " ").take(16)}"
                setTextColor(OP); textSize = 12f; typeface = Typeface.DEFAULT_BOLD
            })
            card.addView(TextView(this).apply { text = entry.getString("name"); setTextColor(Color.WHITE); textSize = 16f; setPadding(0, 6, 0, 6) })
            card.addView(TextView(this).apply { text = "hash ${entry.getString("hash").take(24)}…\nprev ${entry.getString("prev").take(24)}…"; setTextColor(FN); textSize = 11f; typeface = Typeface.MONOSPACE })
            list.addView(card, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = 20 })
        }
    }

    private fun show(entry: JSONObject) {
        val plain = store.open(entry.getInt("index"))
        val view = if (entry.getString("type") in setOf("screenshot", "message")) {
            ImageView(this).apply { setImageBitmap(BitmapFactory.decodeByteArray(plain, 0, plain.size)); adjustViewBounds = true }
        } else {
            ScrollView(this).apply { addView(TextView(context).apply { text = String(plain).take(4000); setPadding(40, 30, 40, 30); textSize = 13f }) }
        }
        AlertDialog.Builder(this).setTitle(entry.getString("name")).setView(view).setPositiveButton("Close", null).show()
    }

    private fun export() {
        val name = "aran-vault-pack-${utcNow("yyyyMMdd-HHmmss")}.json"
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.MIME_TYPE, "application/json")
        }
        val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return
        contentResolver.openOutputStream(uri)!!.use { it.write(store.exportPack().toString(2).toByteArray()) }
        AlertDialog.Builder(this).setTitle("Pack exported")
            .setMessage("Downloads/$name\n\nOnly hashes are in this file, no photos or messages. Hand it to the help desk, then delete it.")
            .setPositiveButton("OK", null).show()
    }
}
