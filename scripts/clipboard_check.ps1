# Clipboard preservation test for invisible-Unicode payloads.
#
# Purpose: show that a payload embedded in text survives a real OS-level
# copy/paste round trip through the Windows clipboard. This is delivery evidence
# (the bytes reach another application), not evidence that a model obeys it.
#
# Usage:
#   pwsh -File scripts/clipboard_check.ps1 -InputFile evidence/clipboard_payload.txt `
#        -OutputFile evidence/clipboard_roundtrip.json

param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)

$ErrorActionPreference = 'Stop'

function Get-Sha256Hex([string]$text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        return ($sha.ComputeHash($bytes) | ForEach-Object { '{0:x2}' -f $_ }) -join ''
    } finally {
        $sha.Dispose()
    }
}

function Get-InvisibleCounts([string]$text) {
    $counts = [ordered]@{
        zero_width_u200b = 0
        zero_width_u200c = 0
        zero_width_u200d = 0
        tag_chars = 0
        variation_selectors = 0
    }
    foreach ($ch in $text.ToCharArray()) {
        $cp = [int]$ch
        if ($cp -eq 0x200B) { $counts.zero_width_u200b++ }
        elseif ($cp -eq 0x200C) { $counts.zero_width_u200c++ }
        elseif ($cp -eq 0x200D) { $counts.zero_width_u200d++ }
        # Tags block and E0100..E01EF are astral: check surrogate pairs.
    }
    for ($i = 0; $i -lt $text.Length - 1; $i++) {
        $hi = [int]$text[$i]
        if ($hi -ge 0xD800 -and $hi -le 0xDB7F) {
            $lo = [int]$text[$i + 1]
            if ($lo -ge 0xDC00 -and $lo -le 0xDFFF) {
                $raw = ([long]($hi - 0xD800) * 0x400) + ([long]($lo - 0xDC00)) + 0x10000
                if ($raw -ge 0xE0000 -and $raw -le 0xE007F) { $counts.tag_chars++ }
                if ($raw -ge 0xE0100 -and $raw -le 0xE01EF) { $counts.variation_selectors++ }
                $i++
            }
        }
    }
    return $counts
}

$inputText = [System.IO.File]::ReadAllText($InputFile, [System.Text.Encoding]::UTF8)
$inputText = $inputText.TrimEnd("`r", "`n")

Set-Clipboard -Value $inputText
Start-Sleep -Milliseconds 150
$clipText = Get-Clipboard -Raw

$same = ($clipText -ceq $inputText)
$inputInvisible = Get-InvisibleCounts $inputText
$clipInvisible = Get-InvisibleCounts $clipText
$firstRun = ''
foreach ($ch in $inputText.ToCharArray()) {
    $cp = [int]$ch
    if ($cp -in @(0x200B, 0x200C, 0x200D) -or $cp -eq 0xFEFF) {
        $firstRun += ('U+{0:X4} ' -f $cp)
        if ($firstRun.Length -gt 120) { break }
    }
}

$record = [ordered]@{
    check = 'windows_clipboard_roundtrip'
    timestamp_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    input_file = (Resolve-Path $InputFile).Path
    input_chars = $inputText.Length
    clipboard_chars = $clipText.Length
    text_identical = $same
    sha256_input_utf8 = (Get-Sha256Hex $inputText)
    sha256_clipboard_utf8 = (Get-Sha256Hex $clipText)
    invisible_counts_input = $inputInvisible
    invisible_counts_clipboard = $clipInvisible
    first_invisible_codepoints = $firstRun.Trim()
    interpretation = 'If text_identical is true, the OS clipboard preserved the invisible payload bytes.'
}

$json = $record | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($OutputFile, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Output ("text_identical={0} input_chars={1} clipboard_chars={2}" -f $same, $inputText.Length, $clipText.Length)
Write-Output ("sha256_input={0}" -f $record.sha256_input_utf8)
Write-Output ("sha256_clipboard={0}" -f $record.sha256_clipboard_utf8)
Write-Output ("invisible_counts_input={0}" -f ($inputInvisible | ConvertTo-Json -Compress))
Write-Output ("invisible_counts_clipboard={0}" -f ($clipInvisible | ConvertTo-Json -Compress))
