package com.netshieldx.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkScheme = darkColorScheme(
    primary = AccentBlue,
    secondary = AccentBlue,
    tertiary = SuccessGreen,
    background = BackgroundDark,
    surface = SurfaceDark,
    surfaceVariant = SurfaceVariantDark,
    onBackground = TextPrimaryDark,
    onSurface = TextPrimaryDark,
    onSurfaceVariant = TextSecondaryDark,
    error = DangerRed,
    primaryContainer = Color(0xFF1F2A37),
    onPrimary = Color.White
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF0969DA),
    secondary = Color(0xFF0969DA),
    tertiary = Color(0xFF1A7F37),
    background = BackgroundLight,
    surface = SurfaceLight,
    surfaceVariant = SurfaceVariantLight,
    onBackground = TextPrimaryLight,
    onSurface = TextPrimaryLight,
    onSurfaceVariant = TextSecondaryLight,
    error = Color(0xFFCF222E)
)

@Composable
fun NetShieldXTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkScheme else LightScheme,
        typography = NetShieldTypography,
        content = content
    )
}
