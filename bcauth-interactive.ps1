# Import necessary functions from bcauth.ps1
. "$PSScriptRoot/bcauth.ps1"

# Function to Open Interactive Logon via Edge or WebView2
function Get-AuthorizationCode {
    Param(
        [string] $tenantID = "common",
        [string] $clientID = "1950a258-227b-4e31-a9cf-717495945fc2", # PowerShell AAD App ID
        [string] $redirectUri = "http://localhost", # Redirect URI for authorization code
        [string] $scopes = "https://api.businesscentral.dynamics.com/.default offline_access"
    )

    # Build the authorization URL
    $authUrl = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/authorize"
    $queryParams = @{
        client_id     = $clientID
        response_type = "code"
        redirect_uri  = $redirectUri
        scope         = $scopes
        response_mode = "query"
    }
    $queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
    $fullUrl = "$authUrl?$queryString"

    # Launch the browser (Edge or WebView2)
    Start-Process "msedge.exe" -ArgumentList $fullUrl

    # Listen for the authorization code on the redirect URI
    Write-Host "Waiting for user to complete authentication..."
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("$redirectUri/")
    $listener.Start()

    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        $response.ContentType = "text/html"
        $response.StatusCode = 200

        # Send a response to the browser
        $responseText = "<html><body><h1>Authentication complete. You may close this window.</h1></body></html>"
        $response.OutputStream.Write((([System.Text.Encoding]::UTF8.GetBytes($responseText))), 0, $responseText.Length)
        $response.Close()

        # Extract the authorization code
        $query = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
        $authCode = $query["code"]

        if ($authCode) {
            Write-Host -ForegroundColor Green "Authorization code received."
            return $authCode
        } else {
            Write-Host -ForegroundColor Red "Authorization code not received."
            return $null
        }
    } finally {
        $listener.Stop()
    }
}

# Function to Exchange Authorization Code for Access Token
function Get-AccessToken {
    Param(
        [string] $tenantID = "common",
        [string] $clientID = "1950a258-227b-4e31-a9cf-717495945fc2", # PowerShell AAD App ID
        [string] $redirectUri = "http://localhost",
        [string] $authCode,
        [string] $scopes = "https://api.businesscentral.dynamics.com/.default offline_access"
    )

    # Token endpoint
    $tokenUrl = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"

    # Request body
    $body = @{
        grant_type    = "authorization_code"
        client_id     = $clientID
        code          = $authCode
        redirect_uri  = $redirectUri
        scope         = $scopes
    }

    # Request token
    try {
        $response = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host -ForegroundColor Green "Access token received."
        return @{
            AccessToken = $response.access_token
            ExpiresOn   = [DateTime]::UtcNow.AddSeconds($response.expires_in)
            RefreshToken = $response.refresh_token
        }
    } catch {
        Write-Host -ForegroundColor Red "Failed to retrieve access token: $($_.Exception.Message)"
        return $null
    }
}

# Main Script
function New-BcAuthInteractive {
    Param(
        [string] $tenantID = "common",
        [string] $scopes = "https://api.businesscentral.dynamics.com/.default offline_access"
    )

    # Step 1: Get the Authorization Code
    $authCode = Get-AuthorizationCode -tenantID $tenantID -scopes $scopes
    if (!$authCode) {
        Write-Host -ForegroundColor Red "Failed to retrieve authorization code."
        return $null
    }

    # Step 2: Exchange Authorization Code for Access Token
    $authContext = Get-AccessToken -tenantID $tenantID -authCode $authCode -scopes $scopes
    if ($authContext) {
        Write-Host "Access Token:" $authContext.AccessToken
        Write-Host "Expires On:" $authContext.ExpiresOn
    } else {
        Write-Host -ForegroundColor Red "Authentication failed."
    }

    return $authContext
}
