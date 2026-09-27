package com.secaudit.webscan

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.secaudit.webscan.i18n.Lang
import com.secaudit.webscan.i18n.Strings
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
import com.secaudit.webscan.ui.theme.Term
import com.secaudit.webscan.ui.theme.WebSecAuditTheme

class MainActivity : ComponentActivity() {

    private val viewModel: ScanViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WebSecAuditTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Term.Bg) {
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
    val lang by viewModel.lang.collectAsState()
    val s = Strings.of(lang)

    var target by remember { mutableStateOf("") }
    var authorised by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = Term.Bg,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Term.Surface,
                    titleContentColor = Term.Accent
                ),
                title = {
                    Text(
                        s.t("ui.app.title"),
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        letterSpacing = 1.sp
                    )
                },
                actions = {
                    LangSwitch(current = lang, onPick = viewModel::setLang)
                    Spacer(Modifier.width(8.dp))
                }
            )
        }
    ) { inner ->
        Column(
            modifier = Modifier
                .padding(inner)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            AuthorizationPanel(s, authorised) { authorised = it }

            Spacer(Modifier.height(16.dp))

            OutlinedTextField(
                value = target,
                onValueChange = { target = it },
                label = { Label(s.t("ui.target.label")) },
                placeholder = { Mono(s.t("ui.target.hint"), Term.TextDim) },
                leadingIcon = {
                    Text(
                        "❯",
                        color = Term.Accent,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )
                },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    fontFamily = FontFamily.Monospace,
                    color = Term.Text
                ),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Term.Accent,
                    unfocusedBorderColor = Term.Border,
                    focusedContainerColor = Term.Surface,
                    unfocusedContainerColor = Term.Surface,
                    cursorColor = Term.Accent
                ),
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    enabled = authorised && state !is ScanState.Running,
                    onClick = { viewModel.scan(target) },
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Term.Accent,
                        contentColor = Term.Bg,
                        disabledContainerColor = Term.SurfaceAlt,
                        disabledContentColor = Term.TextDim
                    )
                ) { Mono(s.t("ui.action.scan"), bold = true) }

                OutlinedButton(
                    onClick = {
                        target = ""
                        viewModel.reset()
                    },
                    shape = RoundedCornerShape(6.dp)
                ) { Mono(s.t("ui.action.reset"), Term.TextDim) }
            }

            Spacer(Modifier.height(20.dp))

            when (val current = state) {
                is ScanState.Idle -> Unit
                is ScanState.Running -> RunningView(current.message)
                is ScanState.Error -> ErrorPanel(s, current.message)
                is ScanState.Done -> ReportView(s, current.report)
            }

            Spacer(Modifier.height(28.dp))
            Text(
                s.t("ui.footer"),
                style = MaterialTheme.typography.bodySmall,
                color = Term.TextDim
            )
            Spacer(Modifier.height(16.dp))
        }
    }
}

// ----------------------------------------------------------------- top-level UI

@Composable
private fun LangSwitch(current: Lang, onPick: (Lang) -> Unit) {
    Row(
        modifier = Modifier
            .border(1.dp, Term.Border, RoundedCornerShape(5.dp))
            .padding(2.dp)
    ) {
        Lang.entries.forEach { lang ->
            val selected = lang == current
            Box(
                modifier = Modifier
                    .background(
                        if (selected) Term.Accent else Color.Transparent,
                        RoundedCornerShape(4.dp)
                    )
                    .clickable { onPick(lang) }
                    .padding(horizontal = 9.dp, vertical = 4.dp)
            ) {
                Text(
                    lang.short,
                    color = if (selected) Term.Bg else Term.TextDim,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp
                )
            }
        }
    }
}

@Composable
private fun AuthorizationPanel(s: Strings, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Panel(accent = if (checked) Term.Accent else Term.Medium) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("!", color = Term.Medium, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(8.dp))
            Label(s.t("ui.auth.title"), Term.Medium)
        }
        Spacer(Modifier.height(10.dp))
        Text(s.t("ui.auth.body"), style = MaterialTheme.typography.bodyMedium, color = Term.Text)
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = checked,
                onCheckedChange = onCheckedChange,
                colors = CheckboxDefaults.colors(
                    checkedColor = Term.Accent,
                    checkmarkColor = Term.Bg,
                    uncheckedColor = Term.BorderBright
                )
            )
            Text(
                s.t("ui.auth.check"),
                style = MaterialTheme.typography.bodyMedium,
                color = Term.Text
            )
        }
    }
}

@Composable
private fun RunningView(message: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(
            modifier = Modifier.size(18.dp),
            strokeWidth = 2.dp,
            color = Term.Accent
        )
        Spacer(Modifier.width(12.dp))
        Mono(message, Term.TextDim)
    }
}

@Composable
private fun ErrorPanel(s: Strings, message: String) {
    Panel(accent = Term.High) {
        Label(s.t("ui.error.title"), Term.High)
        Spacer(Modifier.height(8.dp))
        Mono(message, Term.Text)
    }
}

// -------------------------------------------------------------------- report

@Composable
private fun ReportView(s: Strings, report: ScanReport) {
    Column {
        Panel {
            Mono(report.finalUrl, Term.Accent2, bold = true)
            Spacer(Modifier.height(8.dp))
            Mono(
                s.t("ui.meta", report.httpStatus, report.durationMs, report.findings.size),
                Term.TextDim,
                size = 12
            )
            Spacer(Modifier.height(12.dp))
            ScoreBar(s, report.score)
        }

        if (report.leads.isNotEmpty() || report.caseSummary.isNotBlank()) {
            SectionHeader(s.t("ui.sec.investigation"))
            if (report.caseSummary.isNotBlank()) {
                Panel(accent = Term.Accent2) {
                    Label(s.t("ui.case.title"), Term.Accent2)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        report.caseSummary,
                        style = MaterialTheme.typography.bodyMedium,
                        color = Term.Text
                    )
                }
                Spacer(Modifier.height(10.dp))
            }
            report.leads.forEach {
                LeadPanel(s, it)
                Spacer(Modifier.height(10.dp))
            }
        }

        if (!report.techProfile.isEmpty) {
            SectionHeader(s.t("ui.sec.tech"))
            TechPanel(s, report.techProfile)
            Spacer(Modifier.height(10.dp))
        }

        report.tls?.let {
            SectionHeader(s.t("ui.sec.tls"))
            TlsPanel(s, it)
            Spacer(Modifier.height(10.dp))
        }

        report.securityTxt?.let {
            SectionHeader(s.t("ui.sec.disclosure"))
            SecurityTxtPanel(s, it)
            Spacer(Modifier.height(10.dp))
        }

        SectionHeader(s.t("ui.sec.observations"))
        report.findings.forEach {
            FindingPanel(s, it)
            Spacer(Modifier.height(10.dp))
        }
    }
}

@Composable
private fun ScoreBar(s: Strings, score: Int) {
    val color = when {
        score >= 80 -> Term.Low
        score >= 50 -> Term.Medium
        else -> Term.High
    }
    Mono(s.t("ui.score", score), color, bold = true, size = 13)
    Spacer(Modifier.height(6.dp))
    Box(
        Modifier
            .fillMaxWidth()
            .height(5.dp)
            .background(Term.SurfaceAlt, RoundedCornerShape(3.dp))
    ) {
        Box(
            Modifier
                .fillMaxWidth((score / 100f).coerceIn(0.02f, 1f))
                .height(5.dp)
                .background(color, RoundedCornerShape(3.dp))
        )
    }
}

@Composable
private fun LeadPanel(s: Strings, lead: Lead) {
    Panel(accent = severityColor(lead.severity)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Chip(s.t(lead.severity.key), severityColor(lead.severity))
            Spacer(Modifier.width(6.dp))
            OutlineChip(s.t(lead.confidence.key))
        }
        Spacer(Modifier.height(12.dp))
        Text(
            lead.hypothesis,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = Term.Text
        )
        Spacer(Modifier.height(12.dp))
        Label(s.t("ui.evidence"), Term.TextDim)
        Spacer(Modifier.height(6.dp))
        lead.evidence.forEach { clue ->
            Row(Modifier.padding(vertical = 3.dp)) {
                Text(
                    "▪",
                    color = severityColor(lead.severity),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
                Spacer(Modifier.width(8.dp))
                Text(clue, style = MaterialTheme.typography.bodySmall, color = Term.Text)
            }
        }
        Spacer(Modifier.height(12.dp))
        Divider()
        Spacer(Modifier.height(12.dp))
        Text(lead.soWhat, style = MaterialTheme.typography.bodyMedium, color = Term.Text)
    }
}

@Composable
private fun TechPanel(s: Strings, profile: TechProfile) {
    Panel {
        if (profile.stack.isNotEmpty()) {
            Label(s.t("ui.tech.stack"), Term.TextDim)
            Spacer(Modifier.height(8.dp))
            Mono(profile.stack.joinToString("  ·  "), Term.Accent2, bold = true, size = 13)
            Spacer(Modifier.height(14.dp))
            Divider()
            Spacer(Modifier.height(14.dp))
        }
        Label(s.t("ui.tech.signals"), Term.TextDim)
        Spacer(Modifier.height(8.dp))
        profile.signals.forEach { signal ->
            Column(Modifier.padding(vertical = 4.dp)) {
                Mono("${signal.source}: ${signal.value}", Term.Text, size = 12)
                Mono("  → ${signal.implies}", Term.TextDim, size = 12)
            }
        }
    }
}

@Composable
private fun TlsPanel(s: Strings, tls: TlsInfo) {
    Panel {
        if (!tls.reachable) {
            Label(s.t("ui.tls.unavailable"), Term.Medium)
            Spacer(Modifier.height(8.dp))
            Mono(tls.error ?: s.t("ui.tls.nohandshake"), Term.Text, size = 12)
            return@Panel
        }
        val legacy = tls.accepted.filter { it == "TLSv1" || it == "TLSv1.1" }
        Field(
            s.t("ui.tls.accepted"),
            tls.accepted.joinToString(", "),
            if (legacy.isNotEmpty()) Term.High else Term.Low
        )
        if (tls.rejected.isNotEmpty()) Field(s.t("ui.tls.refused"), tls.rejected.joinToString(", "))
        if (tls.untestable.isNotEmpty()) {
            Field(s.t("ui.tls.untestable"), tls.untestable.joinToString(", "))
        }
        tls.cipherSuite?.let { Field(s.t("ui.tls.suite"), it) }
        tls.certSubject?.let { Field(s.t("ui.tls.cert"), it) }
        tls.certIssuer?.let { Field(s.t("ui.tls.issuer"), it) }
        tls.certDaysRemaining?.let { days ->
            Field(
                s.t("ui.tls.expiresIn"),
                if (days < 0) s.t("ui.tls.expiredAgo", -days) else s.t("ui.tls.daysLeft", days),
                if (days < 30) Term.Medium else Term.Text
            )
        }
        if (tls.certAltNames > 0) Field(s.t("ui.tls.sans"), tls.certAltNames.toString())
    }
}

@Composable
private fun SecurityTxtPanel(s: Strings, txt: SecurityTxt) {
    Panel {
        if (!txt.found) {
            Label(s.t("ui.stxt.missing.title"), Term.Medium)
            Spacer(Modifier.height(8.dp))
            Text(
                s.t("ui.stxt.missing.body"),
                style = MaterialTheme.typography.bodyMedium,
                color = Term.Text
            )
            return@Panel
        }
        txt.url?.let { Field(s.t("ui.stxt.location"), it) }
        if (txt.contacts.isNotEmpty()) {
            Field(s.t("ui.stxt.contact"), txt.contacts.joinToString(", "), Term.Accent2)
        }
        txt.expires?.let {
            Field(
                s.t("ui.stxt.expires"),
                if (txt.expired == true) s.t("ui.stxt.expiredSuffix", it) else it,
                if (txt.expired == true) Term.Medium else Term.Text
            )
        }
        txt.policy?.let { Field(s.t("ui.stxt.policy"), it) }
        txt.encryption?.let { Field(s.t("ui.stxt.encryption"), it) }
        txt.preferredLanguages?.let { Field(s.t("ui.stxt.languages"), it) }
        txt.canonical?.let { Field(s.t("ui.stxt.canonical"), it) }
    }
}

@Composable
private fun FindingPanel(s: Strings, finding: Finding) {
    Panel(accent = severityColor(finding.severity)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Chip(s.t(finding.severity.key), severityColor(finding.severity))
            Spacer(Modifier.width(6.dp))
            OutlineChip(s.t(finding.category.key))
        }
        Spacer(Modifier.height(12.dp))
        Text(
            finding.title,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = Term.Text
        )
        Spacer(Modifier.height(8.dp))
        Text(finding.detail, style = MaterialTheme.typography.bodySmall, color = Term.Text)
        if (finding.severity != Severity.INFO) {
            Spacer(Modifier.height(10.dp))
            Divider()
            Spacer(Modifier.height(10.dp))
            Mono(s.t("ui.fix", finding.remediation), Term.TextDim, size = 12)
        }
    }
}

// --------------------------------------------------------------- building blocks

/**
 * A bordered block with an optional severity stripe down its left edge.
 * `IntrinsicSize.Min` lets the stripe match whatever height the content takes.
 */
@Composable
private fun Panel(accent: Color? = null, content: @Composable () -> Unit) {
    val shape = RoundedCornerShape(6.dp)
    Row(
        Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min)
            .clip(shape)
            .background(Term.Surface)
            .border(1.dp, Term.Border, shape)
    ) {
        if (accent != null) {
            Box(
                Modifier
                    .width(3.dp)
                    .fillMaxHeight()
                    .background(accent)
            )
        }
        Column(
            Modifier
                .weight(1f)
                .padding(16.dp)
        ) { content() }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Spacer(Modifier.height(22.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            "//",
            color = Term.Accent,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp
        )
        Spacer(Modifier.width(8.dp))
        Text(
            title,
            color = Term.Accent,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            letterSpacing = 1.2.sp
        )
    }
    Spacer(Modifier.height(10.dp))
}

@Composable
private fun Label(text: String, color: Color = Term.TextDim) {
    Text(
        text,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 11.sp,
        letterSpacing = 1.sp
    )
}

@Composable
private fun Mono(
    text: String,
    color: Color = Term.Text,
    bold: Boolean = false,
    size: Int = 14
) {
    Text(
        text,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal,
        fontSize = size.sp
    )
}

@Composable
private fun Field(key: String, value: String, valueColor: Color = Term.Text) {
    Column(Modifier.padding(vertical = 5.dp)) {
        Label(key)
        Spacer(Modifier.height(3.dp))
        Mono(value, valueColor, size = 13)
    }
}

@Composable
private fun Divider() {
    Box(
        Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(Term.Border)
    )
}

@Composable
private fun Chip(label: String, color: Color) {
    Box(
        Modifier
            .background(color, RoundedCornerShape(3.dp))
            .padding(horizontal = 7.dp, vertical = 3.dp)
    ) {
        Text(
            label,
            color = Term.Bg,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 10.sp,
            letterSpacing = 0.8.sp
        )
    }
}

@Composable
private fun OutlineChip(label: String) {
    Box(
        Modifier
            .border(1.dp, Term.BorderBright, RoundedCornerShape(3.dp))
            .padding(horizontal = 7.dp, vertical = 3.dp)
    ) {
        Text(
            label,
            color = Term.TextDim,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 10.sp,
            letterSpacing = 0.8.sp
        )
    }
}

private fun severityColor(severity: Severity): Color = when (severity) {
    Severity.HIGH -> Term.High
    Severity.MEDIUM -> Term.Medium
    Severity.LOW -> Term.Low
    Severity.INFO -> Term.Info
}
