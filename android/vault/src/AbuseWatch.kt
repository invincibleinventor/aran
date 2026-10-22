package com.aran.vault

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Typeface
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.text.StaticLayout
import android.text.TextPaint
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream

// On-device abuse classifier. Transparent and offline: every flag names the phrase that fired.
// Mirrors aran/abuse.py on the Desk. A TFLite model could replace classify() without touching callers.
object AbuseLex {
    data class Hit(val category: String, val label: String, val weight: Double, val match: String)

    private val categories = linkedMapOf(
        "surveillance" to Triple(0.40, "Surveillance", listOf(
            "i can see (everything|you|where)", "i know everything", "i know (what|who|where) you",
            "you were at", "i saw you", "check panren", "phone[\\s-]?a?\\s*check",
            "where (are|r) (you|u)", "track(ing)? you", "your location", "watching you")),
        "threat" to Triple(0.40, "Threat", listOf(
            "you will regret", "regret it", "or else", "i('?ll| will) (hurt|kill|find)",
            "consequence", "you'?ll pay", "warn(ing)? you", "nadakkradhe vera", "vidamaaten")),
        "control" to Triple(0.25, "Control", listOf(
            "come home now", "come home", "don'?t lie", "answer me", "right now",
            "every ?day", "you have to", "i told your (mother|amma|parents)", "amma kitta sonna")),
        "isolation" to Triple(0.20, "Isolation/jealousy", listOf(
            "who is \\w+", "why are you (messaging|texting|talking|calling)",
            "stop talking to", "don'?t (talk|message|text) (to )?\\w+", "why (did|are) you with")))

    private val compiled = categories.mapValues { (_, v) -> v.third.map { Regex(it, RegexOption.IGNORE_CASE) } }
    private val tamilCat = mapOf("surveillance" to listOf("கண்காணி", "பார்க்கிற", "செக் பண்ற"),
        "threat" to listOf("அச்சுறுத்த", "கொல்", "விடமாட்டேன்"),
        "control" to listOf("வீட்டுக்கு வா", "பொய் சொல்லாத", "உடனே"))

    // Curated from github.com/ayush-jadaun/AllProfanity (MIT); dictionary-common words removed for precision.
    private val slurScript = listOf("ஓத்தா", "தேவடியா", "கூதி", "புண்ட", "புண்டை", "பொட்டை", "மயிரு", "சுன்னி", "தாயோளி", "ஊம்பு")
    private val slurRoman = listOf("otha", "oththa", "ottha", "thevidiya", "thevdiya", "thevadiya",
        "koothi", "kuthi", "kooti", "punda", "pundai", "pundek", "pottai", "mayiru", "myra", "myru",
        "sunni", "thayoli", "thayli", "oombu", "porukki", "poriki", "baadu", "soothu", "lavda",
        "pundamavaney", "narakoothi", "thevidiya paiyan", "otha pundai", "kena punda",
        "fuck", "fucker", "fucking", "motherfucker", "bitch", "slut", "whore", "bastard", "asshole", "cunt", "randi", "bsdk")
    private val slurMild = listOf("loosu", "muttaal", "naai", "idiot", "stupid")
    private val slurRe = Regex("(?<![\\w])(" + slurRoman.joinToString("|") { Regex.escape(it) } + ")(?![\\w])", RegexOption.IGNORE_CASE)
    private val mildRe = Regex("(?<![\\w])(" + slurMild.joinToString("|") { Regex.escape(it) } + ")(?![\\w])", RegexOption.IGNORE_CASE)
    // Directed-threat construction: target + violent/sexual act + first-person future ("I will … to you").
    // All three must co-occur, so a body-part word or a verb alone never flags. Mirrors abuse.py.
    private val secondRe = Regex("\\b(un|unga|unna|unnai|unnoda|unakku|nee|neenga|your|you)\\b", RegexOption.IGNORE_CASE)
    private val futureRe = Regex("(iduven|iven|uven|duven|ppen|\\bpen\\b|idven|kuren|iren|panren|pannren|pannuven|panniduven|seiven|seiduven|kolluven|adippen|potten|poduven)", RegexOption.IGNORE_CASE)
    private val actRe = Regex("(sorug|nuzhai|serthu|utha|kuthu|vettu|kollu|\\bkol\\b|\\bsudu|nasukk|odaikk|udaikk|\\bizhu|\\bpudi|kizhi|thallu|\\badi|kundi|sunni|mulai|\\bmola\\b|poolu|yoni|கூதி|புண்ட|சுன்னி|குண்டி)", RegexOption.IGNORE_CASE)
    private val engFutRe = Regex("\\b(i\\s?will|i['’]?ll|ima|imma|gonna|i\\s?am\\s?going\\s?to|i['’]?m\\s?going\\s?to)\\b", RegexOption.IGNORE_CASE)
    private val harmRe = Regex("(ruin|destroy|finish you|\\bend you\\b|suffer|\\bregret\\b|leak|expose|\\bviral\\b|nude|naked|screenshot|blackmail|\\bkill\\b|murder|\\bhurt\\b|\\bharm\\b|\\bbeat\\b|\\bslap\\b|acid|\\bburn\\b|\\bstab\\b|strangle|share your|post your|tell your (family|parents|husband|wife|everyone))", RegexOption.IGNORE_CASE)

    fun classify(text: String): List<Hit> {
        val hits = mutableListOf<Hit>()
        for ((cat, pats) in compiled) {
            val m = pats.firstNotNullOfOrNull { it.find(text) }
                ?: tamilCat[cat]?.firstOrNull { text.contains(it) }?.let { Regex(Regex.escape(it)).find(text) }
            if (m != null) hits.add(Hit(cat, categories[cat]!!.second, categories[cat]!!.first, m.value))
        }
        val slur = slurRe.find(text) ?: slurScript.firstOrNull { text.contains(it) }?.let { Regex(Regex.escape(it)).find(text) }
        when {
            slur != null -> hits.add(Hit("abuse_slur", "Abusive language", 0.45, slur.value))
            mildRe.containsMatchIn(text) -> hits.add(Hit("abuse_mild", "Insulting language", 0.10, mildRe.find(text)!!.value))
        }
        if (hits.none { it.category == "threat" }) {
            val harm = actRe.find(text) ?: harmRe.find(text)
            val future = futureRe.containsMatchIn(text) || engFutRe.containsMatchIn(text)
            if (harm != null && future && secondRe.containsMatchIn(text))
                hits.add(Hit("threat", "Threat", 0.40, harm.value))
        }
        return hits
    }

    fun score(hits: List<Hit>) = minOf(1.0, hits.sumOf { it.weight })
    fun band(hits: List<Hit>): String {
        val s = score(hits)
        return if (hits.any { it.category == "threat" } || s >= 0.60) "HIGH" else if (s >= 0.25) "REVIEW" else "NORMAL"
    }
}

class AbuseWatch : NotificationListenerService() {
    private val store by lazy { VaultStore(filesDir, "aran_vault") }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName
        if (pkg == packageName || pkg.startsWith("android") || pkg == "com.android.systemui") return
        val extras = sbn.notification.extras
        val title = extras.getCharSequence("android.title")?.toString().orEmpty()
        val body = (extras.getCharSequence("android.bigText") ?: extras.getCharSequence("android.text"))?.toString().orEmpty()
        if (body.isBlank()) return

        val hits = AbuseLex.classify(body)
        if (AbuseLex.band(hits) == "NORMAL") return
        val msgSha = sha256Hex("$pkg|$title|$body".toByteArray())
        if (store.hasMessage(msgSha)) return

        val app = appLabel(pkg)
        val sender = title.ifBlank { app }
        val png = renderCard(app, sender, body, hits)
        val cats = JSONArray().apply { hits.forEach { put(it.category) } }
        val meta = JSONObject().put("msg_sha", msgSha).put("categories", cats)
            .put("band", AbuseLex.band(hits)).put("preview", body.take(120)).put("sender", sender).put("app", app)
        store.add("message", "$sender · $app", png, meta)
    }

    private fun appLabel(pkg: String): String = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
    } catch (_: Exception) { pkg }

    private fun renderCard(app: String, sender: String, body: String, hits: List<AbuseLex.Hit>): ByteArray {
        val w = 1000; val pad = 48
        val head = TextPaint().apply { color = OP; textSize = 34f; typeface = Typeface.DEFAULT_BOLD; isAntiAlias = true }
        val meta = TextPaint().apply { color = FN; textSize = 28f; isAntiAlias = true }
        val msg = TextPaint().apply { color = Color.WHITE; textSize = 40f; isAntiAlias = true }
        val tag = TextPaint().apply { color = OP; textSize = 26f; typeface = Typeface.DEFAULT_BOLD; isAntiAlias = true }
        val band = AbuseLex.band(hits)
        val cats = hits.joinToString("  ·  ") { it.label } + "   [$band]"
        val msgLayout = StaticLayout.Builder.obtain(body, 0, body.length, msg, w - 2 * pad).build()
        val h = pad + 44 + 42 + 40 + msgLayout.height + 40 + 40 + pad
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val c = Canvas(bmp); c.drawColor(BG)
        var y = pad + 34f
        c.drawText("Captured by Aran · ${utcNow("yyyy-MM-dd HH:mm 'UTC'")}", pad.toFloat(), y, head); y += 46
        c.drawText("$sender  ·  $app", pad.toFloat(), y, meta); y += 56
        c.save(); c.translate(pad.toFloat(), y); msgLayout.draw(c); c.restore(); y += msgLayout.height + 40
        c.drawText(cats, pad.toFloat(), y, tag)
        return ByteArrayOutputStream().also { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
    }
}
