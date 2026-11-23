package com.netshieldx.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.netshieldx.app.ui.theme.AccentBlue

enum class StatusKind { OK, WARNING, INFO }

@Composable
fun StatusCard(
    title: String,
    value: String,
    kind: StatusKind,
    description: String? = null,
    modifier: Modifier = Modifier
) {
    val icon = when (kind) {
        StatusKind.OK -> Icons.Filled.CheckCircle
        StatusKind.WARNING -> Icons.Filled.Error
        StatusKind.INFO -> Icons.Filled.Info
    }
    val tint = when (kind) {
        StatusKind.OK -> MaterialTheme.colorScheme.tertiary
        StatusKind.WARNING -> MaterialTheme.colorScheme.error
        StatusKind.INFO -> MaterialTheme.colorScheme.primary
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.Top
        ) {
            Icon(imageVector = icon, contentDescription = null, tint = tint)
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.titleMedium)
                Text(text = value, style = MaterialTheme.typography.bodyLarge)
                if (!description.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = description,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
fun StatCard(
    title: String,
    value: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(text = value, style = MaterialTheme.typography.titleLarge)
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/**
 * Grafik garis sederhana dari data aktual (riwayat kecepatan unduh).
 * Menampilkan pesan kosong jika belum ada data, bukan grafik palsu.
 */
@Composable
fun TrafficChart(
    values: List<Long>,
    modifier: Modifier = Modifier,
    lineColor: Color = AccentBlue
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(text = "Grafik trafik unduhan", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            if (values.size < 2) {
                Text(
                    text = "Belum ada cukup data. Grafik muncul setelah beberapa detik pemantauan.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Canvas(modifier = Modifier.fillMaxWidth().height(120.dp)) {
                    val max = (values.maxOrNull() ?: 1L).coerceAtLeast(1L).toFloat()
                    val width = size.width
                    val height = size.height
                    val stepX = width / (values.size - 1).coerceAtLeast(1)
                    val path = Path()
                    values.forEachIndexed { index, value ->
                        val x = index * stepX
                        val y = height - (value.toFloat() / max) * (height - 8.dp.toPx()) - 4.dp.toPx()
                        if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
                    }
                    drawPath(path, color = lineColor, style = Stroke(width = 2.dp.toPx()))
                    values.forEachIndexed { index, value ->
                        val x = index * stepX
                        val y = height - (value.toFloat() / max) * (height - 8.dp.toPx()) - 4.dp.toPx()
                        drawCircle(color = lineColor, radius = 3.dp.toPx(), center = Offset(x, y))
                    }
                }
            }
        }
    }
}
