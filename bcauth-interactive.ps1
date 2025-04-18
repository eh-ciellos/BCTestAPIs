function Get-BCInteractiveToken {
    param(
        [string]$TenantId = "46e85934-1fab-4533-a4ad-de92ce1fd81a",
        [string]$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2",
        [string]$Scopes = "https://api.businesscentral.dynamics.com/.default offline_access",
        [switch]$UseEmbeddedWebView
    )

    # Check for Microsoft Edge (optional, for user info)
    $edgePath = (Get-Command "msedge.exe" -ErrorAction SilentlyContinue)?.Source
    if (-not $edgePath) {
        Write-Warning "Microsoft Edge is not installed or not in PATH. Interactive authentication will use the default browser."
    } else {
        Write-Host "Microsoft Edge found at: $edgePath"
    }

    # Only check for WebView2 if -UseEmbeddedWebView is specified
    if ($UseEmbeddedWebView) {
        $webview2Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F1E7E2A0-DA5B-4C6A-8A5A-7A3E2D5A6F7B}" -ErrorAction SilentlyContinue
        if (-not $webview2Reg) {
            Write-Warning "Microsoft Edge WebView2 Runtime is not installed. Embedded web view will not be available."
        } else {
            Write-Host "Microsoft Edge WebView2 Runtime found."
        }
    }

    try {
        # Check if MSAL.PS module is installed
        $msalModule = Get-Module -Name "MSAL.PS" -ListAvailable
        if (-not $msalModule) {
            Write-Host "MSAL.PS module not found. Installing..."
            Install-Module -Name "MSAL.PS" -Scope Local -Force -AllowClobber
        } else {
            Write-Host "MSAL.PS module found."
        }
    } catch {
        Write-Error "Failed to install or load MSAL.PS module: $_"
        return $null
    }
    # Import the MSAL.PS module
    try {
        Import-Module MSAL.PS -Scope Local -Force
    } catch {
        Write-Error "Failed to import MSAL.PS module: $_"
        return $null
    }

    if ($UseEmbeddedWebView) {
        $authResult = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $Scopes -Interactive -UseEmbeddedWebView
    } else {
        $authResult = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $Scopes -Interactive
    }

    if ($authResult) {
        Write-Host "Access Token:" $authResult.AccessToken
        Write-Host "Expires On:" $authResult.ExpiresOn
        return $authResult
    } else {
        Write-Error "Failed to obtain access token."
        return $null
    }
}

# Example usage:
$authResult = Get-BCInteractiveToken -TenantId "46e85934-1fab-4533-a4ad-de92ce1fd81a" `
    -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
    -Scopes "https://api.businesscentral.dynamics.com/.default offline_access"

# Parse and display token claims (optional)
. "c:\repos\BCTestAPIs\bcauth.ps1"
$jwt = Parse-JWTtoken $authResult.AccessToken
Write-Host "Token claims:" ($jwt | ConvertTo-Json -Depth 5)

# Use the token in a Business Central API call
$bcApiUrl = "https://api.businesscentral.dynamics.com/v2.0/$($authResult.TenantId)/Demo/api/v2.0/companies"
$response = Invoke-RestMethod -Uri $bcApiUrl -Headers @{ Authorization = "Bearer $($authResult.AccessToken)" }

Write-Host "API Response:" ($response | ConvertTo-Json -Depth 5)