package com.secaudit.webscan.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.secaudit.webscan.ai.GeminiClient
import com.secaudit.webscan.i18n.Lang
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.HistoryEntry
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.ScanState
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.scanner.RawObservations
import com.secaudit.webscan.scanner.ReportBuilder
import com.secaudit.webscan.scanner.ReportExporter
import com.secaudit.webscan.scanner.WebScanner
import okhttp3.OkHttpClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val scanner = WebScanner()
    private val historyStore = HistoryStore(app)
    private val settings = SettingsStore(app)
    private val gemini = GeminiClient(
        OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(45, TimeUnit.SECONDS)
            .build()
    )

    private val _apiKey = MutableStateFlow(settings.apiKey())
    val apiKey: StateFlow<String> = _apiKey.asStateFlow()

    private val _model = MutableStateFlow(settings.model())
    val model: StateFlow<String> = _model.asStateFlow()

    private val _lang = MutableStateFlow(Lang.fromSystem())
    val lang: StateFlow<Lang> = _lang.asStateFlow()

    private val _state = MutableStateFlow<ScanState>(ScanState.Idle)
    val state: StateFlow<ScanState> = _state.asStateFlow()

    private val _history = MutableStateFlow(historyStore.load())
    val history: StateFlow<List<HistoryEntry>> = _history.asStateFlow()

    /** Kept so a language switch can re-word the report without re-scanning. */
    private var lastObservations: RawObservations? = null

    private val strings: Strings get() = Strings.of(_lang.value)

    fun setLang(lang: Lang) {
        if (lang == _lang.value) return
        _lang.value = lang
        lastObservations?.let { _state.value = ScanState.Done(ReportBuilder(strings).build(it)) }
    }

    fun scan(target: String) {
        val s = strings
        if (target.isBlank()) {
            _state.value = ScanState.Error(s.t("ui.err.noTarget"))
            return
        }
        _state.value = ScanState.Running(s.t("prog.start"))
        viewModelScope.launch {
            try {
                val observations = scanner.collect(target, s) { message ->
                    _state.value = ScanState.Running(message)
                }
                lastObservations = observations
                val report = ReportBuilder(strings).build(observations)
                _state.value = ScanState.Done(report)
                remember(report)
            } catch (t: Throwable) {
                _state.value = ScanState.Error(t.message ?: s.t("ui.err.generic"))
            }
        }
    }

    private fun remember(report: ScanReport) {
        _history.value = historyStore.add(
            HistoryEntry(
                target = report.target,
                finalUrl = report.finalUrl,
                grade = report.grade.label,
                score = report.score,
                epochMs = System.currentTimeMillis()
            )
        )
    }

    fun clearHistory() {
        _history.value = historyStore.clear()
    }

    /** The current report as shareable plain text, or null if there is nothing to share. */
    fun exportText(): String? {
        val done = _state.value as? ScanState.Done ?: return null
        return ReportExporter(strings).toPlainText(done.report)
    }

    fun reset() {
        lastObservations = null
        _state.value = ScanState.Idle
    }

    // ------------------------------------------------------------------- AI

    fun setApiKey(value: String) {
        settings.setApiKey(value)
        _apiKey.value = value.trim()
    }

    fun setModel(value: String) {
        settings.setModel(value)
        _model.value = settings.model()
    }

    val aiReady: Boolean get() = _apiKey.value.isNotBlank()

    /** Asks Gemini to explain the whole audit in plain language, in the current UI language. */
    suspend fun explainReport(): Result<String> {
        val report = (_state.value as? ScanState.Done)?.report
            ?: return Result.failure(IllegalStateException("No report to explain"))
        val s = strings
        val actionable = report.findings.filter { it.severity != Severity.INFO }
        val list = (actionable.ifEmpty { report.findings })
            .joinToString("\n") { "[${s.t(it.severity.key)}] ${it.title}: ${it.detail}" }
        val prompt = s.t(
            "ai.prompt.all",
            s.t("ai.lang"),
            report.finalUrl,
            report.grade.label,
            report.score,
            list
        )
        return gemini.generate(_apiKey.value, prompt, _model.value)
    }
}
