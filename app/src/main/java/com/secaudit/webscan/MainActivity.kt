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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import com.secaudit.webscan.model.Confidence
import com.secaudit.webscan.model.Finding
import com.secaudit.webscan.model.Lead
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.ScanState
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TechProfile
import com.secaudit.webscan.model.TlsInfo
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
            AuthorizationCard(checked = authorised, onCheckedChange = { authorised = it })

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
                ) { Text("Investigate") }

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
                "This tool reads what the target publishes about itself: one page request, " +
                    "handshake-only TLS probes, and the site's disclosure policy. Use it only " +
                    "on systems you own or are explicitly authorised to assess.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }
    }
}

@Composable
private fun AuthorizationCard(checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    SectionCard {
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

@Composable
private fun RunningView(message: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.dp)
        Spacer(Modifier.width(12.dp))
        Text(message)
    }
}

@Composable
private fun ErrorView(message: String) {
    SectionCard {
        Text("Request failed", fontWeight = FontWeight.Bold, color = Color(0xFFD84A4A))
        Spacer(Modifier.height(6.dp))
        Text(message)
    }
}

@Composable
private fun ReportView(report: ScanReport) {
    Column {
        SectionCard {
            Text(report.finalUrl, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text("HTTP ${report.httpStatus} · ${report.durationMs} ms · ${report.findings.size} observations")
            Spacer(Modifier.height(8.dp))
            Text("Header hygiene score: ${report.score}/100", fontWeight = FontWeight.Bold)
        }

        if (report.leads.isNotEmpty() || report.caseSummary.isNotBlank()) {
            SectionHeader("Investigation")
            if (report.caseSummary.isNotBlank()) {
                SectionCard {
                    Text("Case summary", fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    Text(report.caseSummary, style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(Modifier.height(10.dp))
            }
            report.leads.forEach { lead ->
                LeadCard(lead)
                Spacer(Modifier.height(10.dp))
            }
        }

        if (!report.techProfile.isEmpty) {
            SectionHeader("Technology profile")
            TechProfileCard(report.techProfile)
            Spacer(Modifier.height(10.dp))
        }

        report.tls?.let {
            SectionHeader("TLS")
            TlsCard(it)
            Spacer(Modifier.height(10.dp))
        }

        report.securityTxt?.let {
            SectionHeader("Disclosure policy")
            SecurityTxtCard(it)
            Spacer(Modifier.height(10.dp))
        }

        SectionHeader("Observations")
        report.findings.forEach { finding ->
            FindingCard(finding)
            Spacer(Modifier.height(10.dp))
        }
    }
}

@Composable
private fun LeadCard(lead: Lead) {
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Chip(lead.severity.label.uppercase(), severityColor(lead.severity))
            Spacer(Modifier.width(6.dp))
            Chip(lead.confidence.label.uppercase(), confidenceColor(lead.confidence))
        }
        Spacer(Modifier.height(10.dp))
        Text(lead.hypothesis, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(10.dp))
        Text(
            "Evidence",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        Spacer(Modifier.height(4.dp))
        lead.evidence.forEach { clue ->
            Row(Modifier.padding(vertical = 2.dp)) {
                Text("•  ", style = MaterialTheme.typography.bodyMedium)
                Text(clue, style = MaterialTheme.typography.bodyMedium)
            }
        }
        Spacer(Modifier.height(10.dp))
        HorizontalDivider()
        Spacer(Modifier.height(10.dp))
        Text(lead.soWhat, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun TechProfileCard(profile: TechProfile) {
    SectionCard {
        if (profile.stack.isNotEmpty()) {
            Text("Inferred stack", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(profile.stack.joinToString(" · "), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(Modifier.height(12.dp))
        }
        Text(
            "Signals that produced it",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        Spacer(Modifier.height(6.dp))
        profile.signals.forEach { signal ->
            Column(Modifier.padding(vertical = 4.dp)) {
                Text("${signal.source}: ${signal.value}", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "→ ${signal.implies}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                )
            }
        }
    }
}

@Composable
private fun TlsCard(tls: TlsInfo) {
    SectionCard {
        if (!tls.reachable) {
            Text("Could not profile TLS", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(tls.error ?: "No handshake completed.")
            return@SectionCard
        }
        KeyValue("Accepted", tls.accepted.joinToString(", "))
        if (tls.rejected.isNotEmpty()) KeyValue("Refused", tls.rejected.joinToString(", "))
        if (tls.untestable.isNotEmpty()) {
            KeyValue("Not testable here", tls.untestable.joinToString(", "))
        }
        tls.cipherSuite?.let { KeyValue("Cipher suite", it) }
        tls.certSubject?.let { KeyValue("Certificate", it) }
        tls.certIssuer?.let { KeyValue("Issuer", it) }
        tls.certDaysRemaining?.let {
            KeyValue("Expires in", if (it < 0) "expired ${-it} day(s) ago" else "$it day(s)")
        }
        if (tls.certAltNames > 0) KeyValue("SAN entries", tls.certAltNames.toString())
    }
}

@Composable
private fun SecurityTxtCard(txt: SecurityTxt) {
    SectionCard {
        if (!txt.found) {
            Text("Not published", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(
                "No policy at /.well-known/security.txt or /security.txt.",
                style = MaterialTheme.typography.bodyMedium
            )
            return@SectionCard
        }
        txt.url?.let { KeyValue("Location", it) }
        if (txt.contacts.isNotEmpty()) KeyValue("Contact", txt.contacts.joinToString(", "))
        txt.expires?.let {
            KeyValue("Expires", if (txt.expired == true) "$it (expired)" else it)
        }
        txt.policy?.let { KeyValue("Policy", it) }
        txt.encryption?.let { KeyValue("Encryption", it) }
        txt.preferredLanguages?.let { KeyValue("Languages", it) }
        txt.canonical?.let { KeyValue("Canonical", it) }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Chip(finding.severity.label.uppercase(), severityColor(finding.severity))
            Spacer(Modifier.width(6.dp))
            Chip(finding.category.uppercase(), MaterialTheme.colorScheme.primary)
        }
        Spacer(Modifier.height(10.dp))
        Text(finding.title, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(finding.detail, style = MaterialTheme.typography.bodyMedium)
        if (finding.severity != Severity.INFO) {
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            Text(
                "Fix: ${finding.remediation}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.75f)
            )
        }
    }
}

// ------------------------------------------------------------------ building blocks

@Composable
private fun SectionCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(16.dp)) { content() }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Spacer(Modifier.height(20.dp))
    Text(
        title.uppercase(),
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary
    )
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun KeyValue(key: String, value: String) {
    Column(Modifier.padding(vertical = 4.dp)) {
        Text(
            key,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun Chip(label: String, color: Color) {
    Surface(color = color, shape = MaterialTheme.shapes.small) {
        Text(
            label,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}

private fun severityColor(severity: Severity): Color = when (severity) {
    Severity.HIGH -> Color(0xFFD84A4A)
    Severity.MEDIUM -> Color(0xFFE0912F)
    Severity.LOW -> Color(0xFF3E8E41)
    Severity.INFO -> Color(0xFF5A7FA6)
}

private fun confidenceColor(confidence: Confidence): Color = when (confidence) {
    Confidence.HIGH -> Color(0xFF4A4A6A)
    Confidence.MEDIUM -> Color(0xFF6A6A8A)
    Confidence.LOW -> Color(0xFF8A8AA0)
}
