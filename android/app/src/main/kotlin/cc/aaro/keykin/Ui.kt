// The app's few building blocks. Neutral grays for every surface; the one accent colour only on the
// main button and small marks.
package cc.aaro.keykin

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

class Palette(val bg: Color, val card: Color, val line: Color, val text: Color, val dim: Color, val accent: Color, val onAccent: Color, val danger: Color)
val Light = Palette(Color(0xFFF4F4F4), Color(0xFFFFFFFF), Color(0xFFDCDCDC), Color(0xFF1C1C1C), Color(0xFF6B6B6B), Color(0xFF0B7A5C), Color(0xFFFFFFFF), Color(0xFFB3261E))
val Dark = Palette(Color(0xFF161616), Color(0xFF212121), Color(0xFF383838), Color(0xFFEDEDED), Color(0xFF9A9A9A), Color(0xFF3ECFA3), Color(0xFF0C0C0C), Color(0xFFFF7A70))
@Composable fun palette() = if (isSystemInDarkTheme()) Dark else Light

@Composable fun Title(s: String) = BasicText(s, style = TextStyle(color = palette().text, fontSize = 24.sp, fontWeight = FontWeight.Bold))
@Composable fun Head(s: String) = BasicText(s, style = TextStyle(color = palette().text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold))
@Composable fun Body(s: String, modifier: Modifier = Modifier) = BasicText(s, modifier, style = TextStyle(color = palette().text, fontSize = 16.sp, lineHeight = 22.sp))
@Composable fun Dim(s: String, modifier: Modifier = Modifier) = BasicText(s, modifier, style = TextStyle(color = palette().dim, fontSize = 14.sp, lineHeight = 20.sp))
@Composable fun Mono(s: String, modifier: Modifier = Modifier) = BasicText(s, modifier, style = TextStyle(color = palette().dim, fontSize = 13.sp, fontFamily = FontFamily.Monospace))
@Composable fun Warn(s: String) = BasicText(s, style = TextStyle(color = palette().danger, fontSize = 14.sp, lineHeight = 20.sp))

@Composable fun Card(content: @Composable ColumnScope.() -> Unit) {
    val p = palette()
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(p.card).border(1.dp, p.line, RoundedCornerShape(12.dp)).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
}

enum class Kind { Main, Plain, Danger }
@Composable fun Btn(label: String, kind: Kind = Kind.Plain, enabled: Boolean = true, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val p = palette()
    val (bg, fg, edge) = when (kind) { Kind.Main -> Triple(p.accent, p.onAccent, p.accent); Kind.Plain -> Triple(p.card, p.text, p.line); Kind.Danger -> Triple(p.card, p.danger, p.line) }
    Box(modifier.clip(RoundedCornerShape(10.dp)).background(if (enabled) bg else p.line).border(1.dp, if (enabled) edge else p.line, RoundedCornerShape(10.dp))
        .clickable(enabled = enabled, role = Role.Button, onClick = onClick).heightIn(min = 48.dp).padding(horizontal = 18.dp, vertical = 12.dp), contentAlignment = Alignment.Center) {
        BasicText(label, style = TextStyle(color = if (enabled) fg else p.dim, fontSize = 16.sp, fontWeight = if (kind == Kind.Main) FontWeight.SemiBold else FontWeight.Normal))
    }
}

/** A QR code on a white plate, so it scans in dark mode too. */
@Composable fun QrImage(text: String, label: String) {
    val bmp = remember(text) {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(com.google.zxing.EncodeHintType.MARGIN to 0))
        val scale = 8
        Bitmap.createBitmap(m.width * scale, m.height * scale, Bitmap.Config.RGB_565).apply {
            for (y in 0 until height) for (x in 0 until width) setPixel(x, y, if (m.get(x / scale, y / scale)) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
    }
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Image(bmp.asImageBitmap(), contentDescription = label, modifier = Modifier.clip(RoundedCornerShape(10.dp)).background(Color.White).padding(14.dp).widthIn(max = 300.dp).aspectRatio(1f),
            filterQuality = androidx.compose.ui.graphics.FilterQuality.None)
    }
}
