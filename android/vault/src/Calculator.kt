package com.aran.vault

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.Button
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.TextView
import java.text.DecimalFormat

const val SECRET = "1947+58"
const val DECOY = "1111+1"

const val BG = 0xFF12152B.toInt()
const val KEY = 0xFF2A2F55.toInt()
const val FN = 0xFF8E91B5.toInt()
const val OP = 0xFFF0A030.toInt()

fun pill(color: Int, radius: Float = 999f) = GradientDrawable().apply { setColor(color); cornerRadius = radius }

class CalculatorActivity : Activity() {
    private var expr = ""
    private lateinit var exprView: TextView
    private lateinit var resultView: TextView
    private val format = DecimalFormat("#,##0.########")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = BG
        window.navigationBarColor = BG
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(BG); setPadding(40, 120, 40, 60) }
        exprView = TextView(this).apply { textSize = 24f; setTextColor(FN); gravity = Gravity.END }
        resultView = TextView(this).apply { textSize = 64f; setTextColor(Color.WHITE); gravity = Gravity.END; typeface = Typeface.create("sans-serif-light", Typeface.NORMAL) }
        exprView.gravity = Gravity.END or Gravity.BOTTOM
        root.addView(exprView, LinearLayout.LayoutParams(-1, 0, 1f))
        root.addView(resultView, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = 40 })
        val grid = GridLayout(this).apply { columnCount = 4 }
        val keys = listOf("C", "±", "%", "÷", "7", "8", "9", "×", "4", "5", "6", "−", "1", "2", "3", "+", "0", ".", "⌫", "=")
        val size = (resources.displayMetrics.widthPixels - 80) / 4
        for (key in keys) {
            val color = when (key) { "C", "±", "%" -> FN; "÷", "×", "−", "+", "=" -> OP; else -> KEY }
            grid.addView(Button(this).apply {
                text = key; textSize = 26f; setTextColor(Color.WHITE); background = pill(color); isAllCaps = false; stateListAnimator = null
                setOnClickListener { press(key) }
            }, GridLayout.LayoutParams().apply { width = size - 24; height = size - 24; setMargins(12, 12, 12, 12) })
        }
        root.addView(grid)
        setContentView(root)
        render(null)
    }

    override fun onResume() {
        super.onResume()
        expr = ""
        render(null)
    }

    private fun press(key: String) {
        when (key) {
            "C" -> expr = ""
            "⌫" -> expr = expr.dropLast(1)
            "÷" -> appendOp('/')
            "×" -> appendOp('*')
            "−" -> appendOp('-')
            "+" -> appendOp('+')
            "±" -> toggleSign()
            "%" -> evaluate()?.let { expr = clean(it / 100) }
            "=" -> return equals()
            else -> expr += key
        }
        render(null)
    }

    private fun equals() {
        val typed = expr
        val value = evaluate() ?: return
        render(value)
        val target = when (typed) { SECRET -> false; DECOY -> true; else -> null }
        if (target != null) {
            Handler(Looper.getMainLooper()).postDelayed({
                startActivity(Intent(this, VaultActivity::class.java).putExtra("decoy", target))
                overridePendingTransition(0, 0)
            }, 450)
        }
        expr = clean(value)
    }

    private fun appendOp(op: Char) {
        if (expr.isEmpty()) return
        expr = if (expr.last() in "+-*/") expr.dropLast(1) + op else expr + op
    }

    private fun toggleSign() {
        var start = expr.length
        while (start > 0 && (expr[start - 1].isDigit() || expr[start - 1] == '.')) start--
        val unary = start > 0 && expr[start - 1] == '-' && (start == 1 || expr[start - 2] in "+-*/")
        expr = if (unary) expr.removeRange(start - 1, start) else expr.substring(0, start) + "-" + expr.substring(start)
    }

    private fun clean(value: Double) = if (value == Math.floor(value) && !value.isInfinite()) value.toLong().toString() else value.toString()

    private fun evaluate(): Double? = try {
        val numbers = mutableListOf<Double>()
        val ops = mutableListOf<Char>()
        var current = ""
        for ((i, c) in expr.withIndex()) {
            if (c in "+-*/" && !(c == '-' && (i == 0 || expr[i - 1] in "+-*/"))) {
                numbers += current.toDouble(); ops += c; current = ""
            } else current += c
        }
        numbers += current.toDouble()
        var i = 0
        while (i < ops.size) {
            if (ops[i] == '*' || ops[i] == '/') {
                numbers[i] = if (ops[i] == '*') numbers[i] * numbers[i + 1] else numbers[i] / numbers[i + 1]
                numbers.removeAt(i + 1); ops.removeAt(i)
            } else i++
        }
        var total = numbers[0]
        for ((j, op) in ops.withIndex()) total = if (op == '+') total + numbers[j + 1] else total - numbers[j + 1]
        total
    } catch (e: Exception) { null }

    private fun pretty(text: String) = Regex("\\d+(\\.\\d*)?").replace(text) { m ->
        val parts = m.value.split(".")
        format.format(parts[0].toLong()) + if (parts.size > 1) "." + parts[1] else ""
    }.replace("*", " × ").replace("/", " ÷ ").replace("+", " + ").replace(Regex("(?<=\\d)-"), " − ")

    private fun render(result: Double?) {
        if (result != null) {
            exprView.text = pretty(expr)
            resultView.text = if (result.isInfinite() || result.isNaN()) "Error" else format.format(result)
        } else {
            exprView.text = ""
            resultView.text = if (expr.isEmpty()) "0" else pretty(expr)
        }
    }
}
