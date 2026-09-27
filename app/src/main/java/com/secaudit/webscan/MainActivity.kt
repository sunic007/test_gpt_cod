package com.secaudit.webscan

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.secaudit.webscan.model.Finding
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.ScanState
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.ui.ScanViewModel
import com.secaudit.webscan.ui.theme.WebSecAuditTheme

class MainActivity : ComponentActivity() {

    private val viewModel: ScanViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WebSecAuditTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppScreen(viewModel)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppScreen(viewModel: ScanViewModel) {
    val state by viewModel.state.collectAsState()
    var target by remember { mutableStateOf("") }
    var authorised by remember { mutableStateOf(false) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Web Security Audit") }) }
    ) { inner ->
        Column(
            modifier = Modifier
                .padding(inner)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            AuthorizationCard(
                checked = authorised,
                onCheckedChange = { authorised = it }
            )

            Spacer(Modifier.height(16.dp))

            OutlinedTextField(
                value = target,
                onValueChange = { target = it },
                label = { Text("Target URL (site you are authorised to test)") },
                placeholder = { Text("example.com") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    enabled = authorised && state !is ScanState.Running,
                    onClick = { viewModel.scan(target) }
                ) { Text("Run passive scan") }

                OutlinedButton(onClick = {
                    target = ""
                    viewModel.reset()
                }) { Text("Reset") }
            }

            Spacer(Modifier.height(20.dp))

            when (val s = state) {
                is ScanState.Idle -> Unit
                is ScanState.Running -> RunningView(s.message)
                is ScanState.Error -> ErrorView(s.message)
                is ScanState.Done -> ReportView(s.report)
            }

            Spacer(Modifier.height(24.dp))
            Text(
                "This tool performs a single, non-intrusive request and inspects the " +
                    "response headers. Use it only on systems you own or are explicitly " +
                    "authorised to assess.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }
    }
}

@Composable
private fun AuthorizationCard(checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp)) {
            Text("Authorisation required", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Text(
                "Scanning systems without the owner's permission may be illegal. " +
                    "Confirm you own the target or have written authorisation to test it.",
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = checked, onCheckedChange = onCheckedChange)
                Text("I am authorised to test this target.")
            }
        }
    }
}

@Composable
private fun RunningView(message: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(modifier = Modifier.height(24.dp))
        Spacer(Modifier.height(0.dp))
        Text("  $message")
    }
}

@Composable
private fun ErrorView(message: String) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp)) {
            Text("Request failed", fontWeight = FontWeight.Bold, color = Color(0xFFD84A4A))
            Spacer(Modifier.height(6.dp))
            Text(message)
        }
    }
}

@Composable
private fun ReportView(report: ScanReport) {
    Column {
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp)) {
                Text(report.finalUrl, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text("HTTP ${report.httpStatus} · ${report.durationMs} ms · ${report.findings.size} findings")
                Spacer(Modifier.height(8.dp))
                Text("Header hygiene score: ${report.score}/100", fontWeight = FontWeight.Bold)
            }
        }
        Spacer(Modifier.height(12.dp))
        report.findings.forEach { finding ->
            FindingCard(finding)
            Spacer(Modifier.height(10.dp))
        }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityChip(finding.severity)
                Spacer(Modifier.height(0.dp))
                Text("  ${finding.title}", fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(8.dp))
            Text(finding.detail, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Divider()
            Spacer(Modifier.height(8.dp))
            Text(
                "Fix: ${finding.remediation}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.75f)
            )
        }
    }
}

@Composable
private fun SeverityChip(severity: Severity) {
    val color = when (severity) {
        Severity.HIGH -> Color(0xFFD84A4A)
        Severity.MEDIUM -> Color(0xFFE0912F)
        Severity.LOW -> Color(0xFF3E8E41)
        Severity.INFO -> Color(0xFF5A7FA6)
    }
    Surface(color = color, shape = MaterialTheme.shapes.small) {
        Text(
            severity.label.uppercase(),
            color = Color.White,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}
