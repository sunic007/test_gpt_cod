package com.secaudit.webscan

import android.content.Intent
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.secaudit.webscan.i18n.Lang
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.Confidence
import com.secaudit.webscan.model.Finding
import com.secaudit.webscan.model.HistoryEntry
import com.secaudit.webscan.model.Lead
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.ScanState
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TechProfile
import com.secaudit.webscan.model.TlsInfo
import com.secaudit.webscan.ui.MatrixRain
import com.secaudit.webscan.ui.ScanViewModel
import com.secaudit.webscan.ui.theme.Term
import com.secaudit.webscan.ui.theme.WebSecAuditTheme
import kotlinx.coroutines.launch

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
    val history by viewModel.history.collectAsState()
    val apiKey by viewModel.apiKey.collectAsState()
    val model by viewModel.model.collectAsState()
    val s = Strings.of(lang)
    val context = LocalContext.current

    var target by remember { mutableStateOf("") }
    var showLab by remember { mutableStateOf(false) }

    fun shareReport() {
        val text = viewModel.exportText() ?: return
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, s.t("ui.app.title"))
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(Intent.createChooser(send, s.t("ui.action.export")))
    }

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
                    if (state is ScanState.Done) {
                        Text(
                            s.t("ui.action.export"),
                            color = Term.Accent,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            modifier = Modifier
                                .clickable { shareReport() }
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        )
                    }
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
            TabBar(s, showLab) { showLab = it }
            Spacer(Modifier.height(16.dp))

            if (showLab) {
                LabScreen(s)
                return@Column
            }

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
                    enabled = state !is ScanState.Running,
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

            Spacer(Modifier.height(16.dp))
            ApiKeyPanel(s, apiKey, model, { k, m ->
                viewModel.setApiKey(k)
                viewModel.setModel(m)
            })

            Spacer(Modifier.height(20.dp))

            when (val current = state) {
                is ScanState.Idle -> if (history.isNotEmpty()) {
                    HistorySection(
                        s = s,
                        history = history,
                        onOpen = { entry ->
                            target = entry.target
                            viewModel.scan(entry.target)
                        },
                        onClear = viewModel::clearHistory
                    )
                }

                is ScanState.Running -> RunningView(current.message)
                is ScanState.Error -> ErrorPanel(s, current.message)
                is ScanState.Done -> ReportView(
                    s = s,
                    report = current.report,
                    aiReady = apiKey.isNotBlank(),
                    explainAll = viewModel::explainReport
                )
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
private fun TabBar(s: Strings, showLab: Boolean, onSelect: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Term.Border, RoundedCornerShape(6.dp))
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp)
    ) {
        TabPill(s.t("ui.tab.audit"), selected = !showLab, modifier = Modifier.weight(1f)) {
            onSelect(false)
        }
        TabPill(s.t("ui.tab.lab"), selected = showLab, modifier = Modifier.weight(1f)) {
            onSelect(true)
        }
    }
}

@Composable
private fun TabPill(label: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .background(
                if (selected) Term.Accent else Color.Transparent,
                RoundedCornerShape(4.dp)
            )
            .clickable { onClick() }
            .padding(vertical = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            color = if (selected) Term.Bg else Term.TextDim,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            letterSpacing = 1.sp
        )
    }
}

private const val LAB_TERMUX = "pkg install python git -y\n" +
    "git clone https://github.com/stamparm/DSVW\n" +
    "cd DSVW\n" +
    "python dsvw.py"
private const val LAB_PUBLIC = "scanme.nmap.org              # Nmap: owner permits scanning\n" +
    "http://testphp.vulnweb.com    # Acunetix test site (PHP)\n" +
    "http://testhtml5.vulnweb.com  # Acunetix test site (HTML5)\n" +
    "http://demo.testfire.net      # Altoro Mutual demo bank\n" +
    "https://demo.owasp-juice.shop # Juice Shop demo (shared)"
private const val LAB_UP = "docker compose -f lab/docker-compose.yml up -d"
private const val LAB_TARGETS = "http://localhost:3000   # OWASP Juice Shop\n" +
    "http://localhost:8080   # DVWA (admin / password)"
private const val LAB_TOOLS = "nmap -sV -p- 127.0.0.1\n" +
    "whatweb http://localhost:3000\n" +
    "nuclei -u http://localhost:3000\n" +
    "testssl.sh http://localhost:8080"
private const val LAB_LINKS = "https://pwning.owasp-juice.shop/\n" +
    "https://portswigger.net/web-security\n" +
    "https://owasp.org/www-project-top-ten/"

@Composable
private fun LabScreen(s: Strings) {
    Panel(accent = Term.Accent) {
        Label(s.t("lab.title"), Term.Accent)
        Spacer(Modifier.height(10.dp))
        Text(s.t("lab.intro"), style = MaterialTheme.typography.bodyMedium, color = Term.Text)
    }
    Spacer(Modifier.height(10.dp))

    Panel(accent = Term.Medium) {
        Label(s.t("lab.warn.title"), Term.Medium)
        Spacer(Modifier.height(8.dp))
        Text(s.t("lab.warn.body"), style = MaterialTheme.typography.bodyMedium, color = Term.Text)
    }

    // Beyond localhost — targets whose owners publicly authorise testing.
    SectionHeader(s.t("lab.public.title"))
    Panel(accent = Term.Accent2) {
        Text(s.t("lab.public.body"), style = MaterialTheme.typography.bodyMedium, color = Term.Text)
        Spacer(Modifier.height(12.dp))
        CommandBlock(s, LAB_PUBLIC, prompt = false)
    }
    Spacer(Modifier.height(10.dp))

    LabStep(s, "lab.phone.title", "lab.phone.body", LAB_TERMUX)

    SectionHeader(s.t("lab.docker.title"))
    Panel {
        Text(s.t("lab.docker.body"), style = MaterialTheme.typography.bodyMedium, color = Term.Text)
    }
    Spacer(Modifier.height(10.dp))
    LabStep(s, "lab.step1.title", "lab.step1.body", LAB_UP)
    LabStep(s, "lab.targets.title", "lab.targets.body", LAB_TARGETS)
    LabStep(s, "lab.step2.title", "lab.step2.body", LAB_TOOLS)
    LabStep(s, "lab.step3.title", "lab.step3.body", LAB_LINKS)
}

@Composable
private fun LabStep(s: Strings, titleKey: String, bodyKey: String, command: String) {
    SectionHeader(s.t(titleKey))
    Panel {
        Text(s.t(bodyKey), style = MaterialTheme.typography.bodyMedium, color = Term.Text)
        Spacer(Modifier.height(12.dp))
        CommandBlock(s, command)
    }
    Spacer(Modifier.height(10.dp))
}

@Composable
private fun CommandBlock(s: Strings, command: String, prompt: Boolean = true) {
    val clipboard = LocalClipboardManager.current
    Column(
        Modifier
            .fillMaxWidth()
            .background(Term.Bg, RoundedCornerShape(4.dp))
            .border(1.dp, Term.Border, RoundedCornerShape(4.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (prompt) "$ " else "",
                color = Term.Accent,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                modifier = Modifier.weight(1f)
            )
            Text(
                s.t("lab.copy"),
                color = Term.Accent,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 10.sp,
                modifier = Modifier
                    .clickable { clipboard.setText(AnnotatedString(command)) }
                    .padding(4.dp)
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(command, color = Term.Text, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

@Composable
private fun HistorySection(
    s: Strings,
    history: List<HistoryEntry>,
    onOpen: (HistoryEntry) -> Unit,
    onClear: () -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            "// ${s.t("ui.sec.history")}",
            color = Term.Accent,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            letterSpacing = 1.2.sp,
            modifier = Modifier.weight(1f)
        )
        Text(
            s.t("ui.history.clear"),
            color = Term.TextDim,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 11.sp,
            modifier = Modifier
                .clickable { onClear() }
                .padding(6.dp)
        )
    }
    Spacer(Modifier.height(10.dp))
    history.forEach { entry ->
        Panel {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpen(entry) }
            ) {
                Chip(entry.grade, gradeColorForLabel(entry.grade))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Mono(entry.target, Term.Text, bold = true, size = 13)
                    Mono("${entry.score}/100 · ${formatTime(entry.epochMs)}", Term.TextDim, size = 11)
                }
                Text("↻", color = Term.Accent, fontFamily = FontFamily.Monospace, fontSize = 16.sp)
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}

private fun formatTime(epochMs: Long): String =
    java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.ROOT)
        .format(java.util.Date(epochMs))

private fun gradeColorForLabel(label: String): Color = when (label) {
    "A+", "A" -> Term.Low
    "B", "C" -> Term.Medium
    else -> Term.High
}

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
private fun RunningView(message: String) {
    val shape = RoundedCornerShape(6.dp)
    Box(
        Modifier
            .fillMaxWidth()
            .height(210.dp)
            .clip(shape)
            .background(Color(0xFF04070A))
            .border(1.dp, Term.Border, shape)
    ) {
        MatrixRain(modifier = Modifier.matchParentSize(), running = true)

        // A readable strip at the bottom keeps the progress line legible over the rain.
        Row(
            modifier = Modifier
                .align(Alignment.BottomStart)
                .fillMaxWidth()
                .background(Color(0xCC04070A))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            BlinkingCursor()
            Spacer(Modifier.width(8.dp))
            Mono(message, Term.Accent, size = 13)
        }
    }
}

@Composable
private fun BlinkingCursor() {
    val transition = rememberInfiniteTransition(label = "cursor")
    val alpha by transition.animateFloat(
        initialValue = 1f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(600),
            repeatMode = RepeatMode.Reverse
        ),
        label = "cursorAlpha"
    )
    Text(
        "▮",
        color = Term.Accent.copy(alpha = alpha),
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 14.sp
    )
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
private fun ReportView(
    s: Strings,
    report: ScanReport,
    aiReady: Boolean,
    explainAll: suspend () -> Result<String>
) {
    Column {
        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                GradeBadge(report.grade)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Mono(report.finalUrl, Term.Accent2, bold = true, size = 13)
                    Spacer(Modifier.height(4.dp))
                    Mono(
                        s.t("ui.meta", report.httpStatus, report.durationMs, report.findings.size),
                        Term.TextDim,
                        size = 11
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            ScoreBar(s, report.score)
        }

        if (aiReady) {
            Spacer(Modifier.height(12.dp))
            ExplainAllPanel(s, explainAll)
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

        report.dns?.let {
            SectionHeader(s.t("ui.sec.dns"))
            DnsPanel(s, it)
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
private fun GradeBadge(grade: com.secaudit.webscan.model.Grade) {
    val color = when (grade) {
        com.secaudit.webscan.model.Grade.A_PLUS,
        com.secaudit.webscan.model.Grade.A -> Term.Low
        com.secaudit.webscan.model.Grade.B,
        com.secaudit.webscan.model.Grade.C -> Term.Medium
        else -> Term.High
    }
    Box(
        Modifier
            .background(color, RoundedCornerShape(6.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Text(
            grade.label,
            color = Term.Bg,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp
        )
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
        if (tls.certKeyBits > 0) {
            Field(s.t("ui.tls.key"), "${tls.certKeyType ?: "?"} ${tls.certKeyBits}")
        }
        tls.certSigAlg?.let {
            val weak = it.contains("SHA1", true) || it.contains("MD5", true)
            Field(s.t("ui.tls.sig"), it, if (weak) Term.High else Term.Text)
        }
        if (tls.certChainLength > 0) Field(s.t("ui.tls.chain"), tls.certChainLength.toString())
        tls.certSubject?.let { Field(s.t("ui.tls.cert"), it) }
        tls.certIssuer?.let { Field(s.t("ui.tls.issuer"), it) }
        tls.certCoversHost?.let {
            Field(s.t("ui.tls.covers"), s.t(if (it) "word.yes" else "word.no"), if (it) Term.Low else Term.High)
        }
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
private fun DnsPanel(s: Strings, dns: com.secaudit.webscan.model.DnsInfo) {
    Panel {
        if (dns.error != null) {
            Label(s.t("ui.dns.unavailable"), Term.Medium)
            Spacer(Modifier.height(8.dp))
            Mono(dns.error, Term.Text, size = 12)
            return@Panel
        }
        Field(
            s.t("ui.dns.caa"),
            if (dns.hasCaa) dns.caaRecords.joinToString("\n") else s.t("word.no"),
            if (dns.hasCaa) Term.Low else Term.Medium
        )
        Field(
            s.t("ui.dns.dnssec"),
            s.t(if (dns.dnssec) "word.yes" else "word.no"),
            if (dns.dnssec) Term.Low else Term.Medium
        )
        Field(
            s.t("ui.dns.spf"),
            dns.spf ?: s.t("word.no"),
            if (dns.spf != null) Term.Low else Term.Medium
        )
        Field(
            s.t("ui.dns.dmarc"),
            dns.dmarcPolicy ?: s.t(if (dns.dmarcPresent) "word.yes" else "word.no"),
            if (dns.dmarcPresent && dns.dmarcPolicy != "none") Term.Low else Term.Medium
        )
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

/** The single "explain the whole audit" button and its result, shown atop the report. */
@Composable
private fun ExplainAllPanel(s: Strings, explainAll: suspend () -> Result<String>) {
    val scope = rememberCoroutineScope()
    var ai by remember { mutableStateOf<AiState>(AiState.Idle) }

    Panel(accent = Term.Accent2) {
        when (val current = ai) {
            is AiState.Idle, is AiState.Error -> {
                Text(
                    "✦ ${s.t("ai.explainAll")}",
                    color = Term.Accent2,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            ai = AiState.Loading
                            scope.launch {
                                ai = explainAll().fold(
                                    onSuccess = { AiState.Done(it) },
                                    onFailure = { AiState.Error(it.message ?: "error") }
                                )
                            }
                        }
                        .padding(vertical = 4.dp)
                )
                if (current is AiState.Error) {
                    Spacer(Modifier.height(6.dp))
                    Mono(current.message, Term.High, size = 11)
                }
            }

            is AiState.Loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                Mono(s.t("ai.explaining"), Term.TextDim, size = 13)
            }

            is AiState.Done -> {
                Label(s.t("ai.explainAll"), Term.Accent2)
                Spacer(Modifier.height(8.dp))
                Text(current.text, style = MaterialTheme.typography.bodyMedium, color = Term.Text)
            }
        }
    }
}

private sealed interface AiState {
    data object Idle : AiState
    data object Loading : AiState
    data class Done(val text: String) : AiState
    data class Error(val message: String) : AiState
}

@Composable
private fun ApiKeyPanel(
    s: Strings,
    currentKey: String,
    currentModel: String,
    onSave: (String, String) -> Unit
) {
    var open by remember { mutableStateOf(false) }
    var keyField by remember(currentKey) { mutableStateOf(currentKey) }
    var modelField by remember(currentModel) { mutableStateOf(currentModel) }
    val set = currentKey.isNotBlank()

    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = Term.Accent,
        unfocusedBorderColor = Term.Border,
        focusedContainerColor = Term.Surface,
        unfocusedContainerColor = Term.Surface,
        cursorColor = Term.Accent
    )
    val fieldTextStyle = MaterialTheme.typography.bodyMedium.copy(
        fontFamily = FontFamily.Monospace,
        color = Term.Text
    )

    Panel(accent = if (set) Term.Accent else Term.Border) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clickable { open = !open }
        ) {
            Text("✦ ", color = Term.Accent2, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
            Label(s.t("ai.title"), if (set) Term.Accent else Term.TextDim)
            Spacer(Modifier.weight(1f))
            Text(if (open) "▾" else "▸", color = Term.TextDim, fontFamily = FontFamily.Monospace)
        }
        if (open) {
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = keyField,
                onValueChange = { keyField = it },
                singleLine = true,
                placeholder = { Mono(s.t("ai.key.hint"), Term.TextDim, size = 12) },
                textStyle = fieldTextStyle,
                colors = fieldColors,
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = modelField,
                onValueChange = { modelField = it },
                singleLine = true,
                placeholder = { Mono(s.t("ai.model.hint"), Term.TextDim, size = 12) },
                textStyle = fieldTextStyle,
                colors = fieldColors,
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(
                    onClick = { onSave(keyField, modelField); open = false },
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Term.Accent,
                        contentColor = Term.Bg
                    )
                ) { Mono(s.t("ai.save"), bold = true) }
                Spacer(Modifier.width(12.dp))
                Mono(s.t("ai.get"), Term.TextDim, size = 11)
            }
            if (set) {
                Spacer(Modifier.height(8.dp))
                Mono(s.t("ai.saved"), Term.Low, size = 11)
            }
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
