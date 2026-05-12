package xyz.umbrellax.testharness

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/**
 * Smoke-test Activity: 6 кнопок — по одной на scenario. Результат каждого —
 * строка в лог view. Реальные E2E реализации сценариев — в Блоке 7.10
 * integration milestone.
 *
 * Smoke-test Activity: six buttons — one per scenario. Each outcome lands
 * as a line in the log view. The real end-to-end scenario implementations
 * arrive in Block 7.10 integration milestone.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var logView: TextView
    private lateinit var scenarios: TestScenarios

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        scenarios = TestScenarios(this)

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val titles = listOf(
            "1. Registration flow",
            "2. Send/receive Cloud text",
            "3. Send/receive Secret text",
            "4. 1-1 Secret call (compliance-gate)",
            "5. Multi-device bootstrap",
            "6. Catastrophic recovery"
        )
        titles.forEachIndexed { idx, title ->
            val button = Button(this).apply { text = title }
            button.setOnClickListener {
                lifecycleScope.launch {
                    val result = scenarios.run(idx + 1)
                    appendLog("[scenario-${idx + 1}] $result")
                }
            }
            root.addView(button)
        }

        logView = TextView(this).apply { textSize = 10f }
        val scroll = ScrollView(this).apply { addView(logView) }
        root.addView(scroll)

        setContentView(root)
    }

    private fun appendLog(msg: String) {
        logView.append("$msg\n")
    }
}
