function Test-IsPortOpen {
    param(
        [string]$Name,
        [int]$Port
    )
    
    $mgr = New-Object -ComObject "HNetCfg.FwMgr"
    $allow = $null
    $mgr.IsPortAllowed($Name, 2, $Port, "", 6, [ref]$allow, $null)
    $allow
}

foreach($i in 1..65555){
    if (Test-IsPortOpen "System" $i) {
        Write-Host "System $i"
    }
}