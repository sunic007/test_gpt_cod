package com.secaudit.webscan.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.secaudit.webscan.i18n.Lang
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.ScanState
import com.secaudit.webscan.scanner.RawObservations
import com.secaudit.webscan.scanner.ReportBuilder
import com.secaudit.webscan.scanner.WebScanner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ScanViewModel : ViewModel() {

    private val scanner = WebScanner()

    private val _lang = MutableStateFlow(Lang.fromSystem())
    val lang: StateFlow<Lang> = _lang.asStateFlow()

    private val _state = MutableStateFlow<ScanState>(ScanState.Idle)
    val state: StateFlow<ScanState> = _state.asStateFlow()

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
                _state.value = ScanState.Done(ReportBuilder(strings).build(observations))
            } catch (t: Throwable) {
                _state.value = ScanState.Error(t.message ?: s.t("ui.err.generic"))
            }
        }
    }

    fun reset() {
        lastObservations = null
        _state.value = ScanState.Idle
    }
}
