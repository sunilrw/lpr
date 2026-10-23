# ==============================================================================
# 🟦 1. POWERSHELL MODULE & NATIVE PIPELINE INTEGRATION
# ==============================================================================
# Run `lpr.exe` directly in PowerShell and convert output into native PSObjects:

function Invoke-LprQuery {
    param(
        [Parameter(Mandatory=$true)][string]$Sql,
        [string]$File = "",
        [string]$InputFormat = "auto"
    )
    $argsList = @("-q", "-o", "json", "-i", $InputFormat)
    if ($File -ne "") { $argsList += @("-f", $File) }
    $argsList += $Sql
    $rawJson = & lpr @argsList
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rawJson)) { return @() }
    return ($rawJson | ConvertFrom-Json)
}

# Example 1: Query IIS W3C 5xx errors as native PowerShell objects:
# $errors = Invoke-LprQuery "SELECT * FROM 'D:\Logs\AcmeStore\*.log' WHERE sc-status LIKE '5%'"
# $errors | Where-Object { [int]$_.time_taken -gt 1000 } | Format-Table c_ip, cs_uri_stem, sc_status, time_taken

# Example 2: Pipe PowerShell Get-Content / Get-WinEvent into lpr stdin:
# Get-Content .\samples\iis_u_ex.log | lpr -i:W3C -o:json "SELECT sc-status, COUNT(*) AS hits FROM stdin GROUP BY sc-status" | ConvertFrom-Json

# Example 3: Call running lpr REST API (`lpr serve`) from PowerShell:
# $res = Invoke-RestMethod -Uri "http://127.0.0.1:8080/v1/query" -Method Post -ContentType "application/json" `
#        -Body (@{ sql = "SELECT * FROM 'samples/iis_u_ex.log' WHERE sc-status LIKE '5%'" } | ConvertTo-Json)
# $res.data | Format-Table

