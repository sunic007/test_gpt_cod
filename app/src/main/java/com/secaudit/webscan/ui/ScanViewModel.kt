package com.secaudit.webscan.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.secaudit.webscan.model.ScanState
import com.secaudit.webscan.scanner.WebScanner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ScanViewModel(
    private val scanner: WebScanner = WebScanner()
) : ViewModel() {

    private val _state = MutableStateFlow<ScanState>(ScanState.Idle)
    val state: StateFlow<ScanState> = _state.asStateFlow()

    fun scan(target: String) {
        if (target.isBlank()) {
            _state.value = ScanState.Error("Enter a target URL first.")
            return
        }
        _state.value = ScanState.Running("Requesting ${scanner.normalizeTarget(target)} …")
        viewModelScope.launch {
            try {
                val report = scanner.scan(target)
                _state.value = ScanState.Done(report)
            } catch (t: Throwable) {
                _state.value = ScanState.Error(t.message ?: "The request failed.")
            }
        }
    }

    fun reset() {
        _state.value = ScanState.Idle
    }
}
