# Simple internet connection test script
# Do not touch LAN cable, adapter, router, Wi-Fi access point or switch during executing this script
# -----------------------------
# Copyright (c) 2023 mkaraki

# =============================================
# Config
# =============================================

$dig_test_domains = @("example.com")
$ping_destinations_v4 = @("1.0.0.1", "8.8.4.4")
$ping_destinations_v6 = @("2606:4700:4700::1001", "2606:4700:4700::1111")
$http_test_destinations = @("http://example.com/", "http://google.com/")
$https_test_destinations = @("https://example.com/", "https://google.com/")
$https_quic_test_destinations = @("https://cloudflare-quic.com/")
$display_routing_table = $false
$ping_count = 2

$save_tech_support_info = $true
$save_simplified_tech_support_info = $false # This not work well
$tech_support_info_path = "tech_support_info.xml"
$simplified_tech_support_info_path = "simplified_tech_support_info.json"

# =============================================
# Programs
# =============================================

Write-Host "Simple internet connection test script"
Write-Host "Do not touch LAN cable, adapter, router, Wi-Fi access point or switch during the test" -ForegroundColor Red -BackgroundColor Black
Write-Host "-----------------------------"


function Write-NonImportantDescription {
    Write-Host $args -ForegroundColor DarkGray -BackgroundColor Black
}

function Write-NonImportantTest {
    Write-Host $args -ForegroundColor DarkGray -BackgroundColor Black -NoNewline
}

function Write-Success {
    Write-Host $args -ForegroundColor Green -BackgroundColor Black
}

function Write-NonImportantSuccess {
    Write-Host $args -ForegroundColor DarkGreen -BackgroundColor Black
}

function Write-Fail {
    Write-Host $args -ForegroundColor Red -BackgroundColor Black
}

function Write-NonImportantFail {
    Write-Host $args -ForegroundColor DarkRed -BackgroundColor Black
}
function Write-Warn {
    Write-Host $args -ForegroundColor Yellow -BackgroundColor Black
}

function Write-NonImportantWarn {
    Write-Host $args -ForegroundColor DarkYellow -BackgroundColor Black
}

function Write-IPv4OnlyFailNotice {
    Write-NonImportantDescription " This cause some sites are not reachable."
    Write-NonImportantDescription " If your network is IPv6 sigle stack, this is not a problem"
}

function Write-IPv6OnlyFailNotice {
    Write-NonImportantDescription " If your network won't support IPv6, this is not a problem"
}

function End-Testing($is_test_success, $test_artifacts, $simplified_test_artifacts, $warns, $fails) {
    Write-Host ""

    if ($is_test_success -eq $true) {
        Write-Host "-----------------------------"
        Write-Success "All tests passed"
        Write-Host "-----------------------------"
        Write-Host ""
        if ($warns.Count -gt 0) {
            Write-Host "There are some warnings. Check yellow messages below."
        }
        else {
            Write-Host "Your network is working well."
        }
        Write-Host "If probrem continues, probrems may not in your network."
    }
    else {
        Write-Host "-----------------------------"
        Write-Fail "Test failed"
        Write-Host "-----------------------------"
        Write-Host ""
        Write-Host "Check red or yellow messages below."
    }

    Write-Host ""

    if ($warns.Count -gt 0 -or $fails.Count -gt 0) {
        Write-Host "Probrems:"

        foreach ($warn in $warns) {
            Write-Warn " [WARN]" $warn
        }
        foreach ($fail in $fails) {
            Write-Fail " [FATAL]" $fail
        }
    }


    Write-Host ""
    
    if ($save_simplified_tech_support_info -or $save_tech_support_info) {
        $test_artifacts['warns'] = $warns
        $test_artifacts['fails'] = $fails
        $simplified_test_artifacts['warns'] = $warns
        $simplified_test_artifacts['fails'] = $fails

        Write-Host -NoNewline "Saving test results..."
        Write-NonImportantDescription "[ONGOING]"

        if ($save_tech_support_info) {
            Write-NonImportantTest " Exporting tech support info..."
            $test_artifacts | Export-Clixml -Depth 100 -Encoding utf8 -Path $tech_support_info_path
            Write-NonImportantSuccess "[DONE]"
            Write-NonImportantDescription "  =>" $tech_support_info_path
        }
    
        if ($save_simplified_tech_support_info) {
            Write-NonImportantTest " Exporting simplified tech support info..."
            $simplified_test_artifacts | ConvertTo-Json -Depth 100 | Out-File -Encoding utf8 -FilePath $simplified_tech_support_info_path
            Write-NonImportantSuccess "[DONE]"
            Write-NonImportantDescription "  =>" $simplified_tech_support_info_path
        }
    }

    if ($is_test_success -eq $true) {
        exit 0
    }
    else {
        exit 1
    }
}

$test_res = @{}
$simple_test_res = @{}
$warns = @()
$fails = @()

# =============================================
# Predefined test scripts
# =============================================

function Test-PingReach($ping_destinations, $prefix = " ") {
    $ping_res = @{}

    foreach ($ping_destination in $ping_destinations) {
        Write-NonImportantTest ($prefix + "ping $($ping_destination)")

        $ping_test_res = Test-Connection $ping_destination -Ping -ErrorAction SilentlyContinue -Count $ping_count
        $ping_res[$ping_destination] = $ping_test_res
        $success_reply_cnt = ($ping_test_res.Reply | Where-Object -Property Status -EQ -Value 0).Count
        if ($success_reply_cnt -eq $ping_count) {
            Write-NonImportantSuccess " [OK] ($($success_reply_cnt)/$($ping_count))"
        }
        else {
            Write-NonImportantWarn " [NG]"
        }

        if ($success_reply_cnt -lt $ping_count) {
            foreach ($res in $ping_test_res.Reply) {
                Write-NonImportantTest " " ($prefix + "$($res.Address) => ")
                
                if ($res.Status -eq 0) {
                    Write-Host $($res.Status) -NoNewline -ForegroundColor DarkGreen -BackgroundColor Black
                }
                else {
                    Write-Host $($res.Status) -NoNewline -ForegroundColor DarkRed -BackgroundColor Black
                }
    
                Write-NonImportantDescription " ($($res.RoundtripTime)ms)"
            }
        }
    }

    return $ping_res
}

# =============================================
# Get Interfaces and check interface #
# =============================================

Write-Host -NoNewline "Checking network adapters..."

$net_adapters = Get-NetAdapter -IncludeHidden
[array] $up_net_adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
$up_net_adapters_cnt = $up_net_adapters.Count
[array] $up_net_adapters_indexes = $up_net_adapters | ForEach-Object ifIndex

$test_res['net_adapters'] = $net_adapters
$test_res['up_net_adapters'] = $up_net_adapters
$test_res['up_net_adapters_cnt'] = $up_net_adapters_cnt
$test_res['up_net_adapters_indexes'] = $up_net_adapters_indexes

$simple_test_res['net_adapters'] = $net_adapters
$simple_test_res['up_net_adapters_indexes'] = $up_net_adapters_indexes

if ($up_net_adapters_cnt -gt 0) {
    Write-Success "[PASS]"
    Write-NonImportantDescription " $($up_net_adapters_cnt) adapters are up"
}
else {
    Write-Fail "[FAIL] No network adapters are up"
    $fails += "No network adapters are up [0 non hidden adapters are up]"
    End-Testing $false $test_res $simple_test_res $warns, $fails
}

# =============================================
# Get assigned IPs
# =============================================

Write-Host -NoNewline "Getting assigned ip addresses..."
Write-NonImportantDescription "[ONGOING]"

$apipa_cnt = 0;
$addr_cnt = 0;

$all_assigned_ips = @{}

foreach ($adapter in $up_net_adapters) {
    Write-NonImportantDescription " Adapters:"
    Write-NonImportantDescription " - [$($adapter.ifIndex)]$($adapter.Name): $($adapter.Status); $($adapter.InterfaceDescription); $($adapter.MacAddress); $($adapter.LinkSpeed)"

    [array]$assigned_ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex | Where-Object { $_.AddressFamily -eq "IPv4" }
    $all_assigned_ips[$adapter.ifIndex] = $assigned_ip

    foreach ($ip in $assigned_ip) {
        if ($ip.AddressFamily -eq "IPv4" -and $ip.IPAddress.StartsWith("169.254")) {
            Write-NonImportantDescription "   - [APIPA] [$($ip.Type)] $($ip.IPAddress)/$($ip.PrefixLength) $($ip.PrefixOrigin) $($ip.SuffixOrigin)" -ForegroundColor Red -BackgroundColor Black
            $apipa_cnt++
        }
        else {
            Write-NonImportantDescription "   - [$($ip.AddressState)] [$($ip.Type)] $($ip.IPAddress)/$($ip.PrefixLength) $($ip.PrefixOrigin) $($ip.SuffixOrigin)"
            $addr_cnt++
        }
    }
}

$test_res['assigned_ip'] = $all_assigned_ips
$test_res['apipa_cnt'] = $apipa_cnt
$test_res['addr_cnt'] = $addr_cnt

$simple_test_res['assigned_ip'] = $all_assigned_ips | Select-Object -Property IPAddress, InterfaceAlias, InterfaceIndex, PrefixLength, PrefixOrigin, SuffixOrigin
$simple_test_res['apipa_cnt'] = $apipa_cnt
$simple_test_res['addr_cnt'] = $addr_cnt

# =============================================
# Check assigned IPs #
# =============================================

Write-Host -NoNewline "Checking assigned ip addresses..."

if ($up_net_adapters.Count -eq $apipa_cnt) {
    Write-Fail "[FAIL] All adapters have APIPA addresses"
    $fails += "All adapters have APIPA addresses [$($apipa_cnt) adapters have APIPA addresses, $($up_net_adapters.Count) non hidden adapters are up]"
    End-Testing $false $test_res $simple_test_res $warns, $fails
}
elseif ($apipa_cnt -gt 0) {
    Write-Warn "[WARN] Some adapters have APIPA addresses"
    $warns += "Some adapters have APIPA addresses [$($apipa_cnt) adapters have APIPA addresses, $($up_net_adapters.Count) non hidden adapters are up]"
}

if ($addr_cnt -eq 0) {
    Write-Fail "[FAIL] No ip addresses are assigned"
    $fails += "No ip addresses are assigned [0 ip addresses are assigned]"
    End-Testing $false $test_res $simple_test_res $warns, $fails
}
else {
    Write-Success "[PARTIAL PASS]"
    Write-NonImportantDescription " This test is partially evaluate following:"
    Write-NonImportantDescription "  - There are $($apipa_cnt) APIPA addresses assigned (out of $($up_net_adapters.Count) adapters)"
    Write-NonImportantDescription "  - There are $($addr_cnt) ip addresses assigned"
}

# =============================================
# Get Gateways
# =============================================

Write-Host -NoNewline "Getting network configuration..."

$net_config = Get-NetIPConfiguration -Detailed -All
$test_res['net_config'] = $net_config


Write-Success "[DONE]"

[array]$v4_gw = $net_config.IPv4DefaultGateway | Where-Object { $null -ne $_.NextHop }
$v4_gw_cnt = $v4_gw.Count
Write-NonImportantDescription " - v4 gateways:"
foreach ($gw in $v4_gw) {
    Write-NonImportantDescription "   - $($gw.NextHop) $($gw.Metric)"
}

$test_res['v4_gw'] = $v4_gw
$test_res['v4_gw_cnt'] = $v4_gw_cnt
$simple_test_res['v4_gw'] = $v4_gw | Select-Object -Property NextHop, InterfaceAlias, InterfaceIndex, RouteMetric

[array]$v6_gw = $net_config.IPv6DefaultGateway | Where-Object { $null -ne $_.NextHop }
$v6_gw_cnt = $v6_gw.Count
Write-NonImportantDescription " - v6 gateways:"
foreach ($gw in $v6_gw) {
    Write-NonImportantDescription "   - $($gw.NextHop) $($gw.Metric)"
}

$test_res['v6_gw'] = $v6_gw
$test_res['v6_gw_cnt'] = $v6_gw_cnt
$simple_test_res['v6_gw'] = $v6_gw | Select-Object -Property NextHop, InterfaceAlias, InterfaceIndex, RouteMetric

# =============================================
# Check Gateways #
# =============================================

Write-Host -NoNewline "Checking v4 gateway settings..."
if ($v4_gw_cnt -eq 0) {
    Write-Warn "[WARN] No v4 gateways are set"
    $warns += "No v4 gateways are set [$($v4_gw_cnt) v4 gateways are set]"
    Write-IPv4OnlyFailNotice
}
else {
    Write-Success "[PASS] $($v4_gw_cnt)"

    foreach ($gw in $v4_gw) {
        $pingres = Test-PingReach $gw.NextHop
        if ($pingres.Count -eq 0) {
            Write-NonImportantWarn " [WARN] $($gw.NextHop) didn't reply ICMP echo request"
            $warns += "IPv4 Gateway, $($gw.NextHop) not reply ICMP Echo request ($($v4_gw_cnt) v4 gateways are set)"
        }
    }
}

Write-Host -NoNewline "Checking v6 gateway settings..."

if ($v6_gw_cnt -eq 0) {
    Write-Warn "[WARN] No v6 gateways are set"
    $warns += "No v6 gateways are set [$($v6_gw_cnt) v6 gateways are set]"
    Write-IPv6OnlyFailNotice
}
else {
    Write-Success "[PASS] $($v6_gw_cnt)"

    foreach ($gw in $v6_gw) {
        $pingres = Test-PingReach $gw.NextHop
        if ($pingres.Count -eq 0) {
            Write-NonImportantWarn " [WARN] $($gw.NextHop) didn't reply ICMP echo request"
            $warns += "IPv6 Gateway, $($gw.NextHop) not reply ICMP Echo request ($($v6_gw_cnt) v6 gateways are set)"
        }
    }
}

Write-Host -NoNewline "Checking gateway settings..."

if ($v4_gw_cnt -eq 0 -and $v6_gw_cnt -eq 0) {
    Write-Fail "[FAIL] No gateways are set"
    $fails += "No gateways are set [$($v4_gw_cnt) v4 gateways are set, $($v6_gw_cnt) v6 gateways are set]"
    End-Testing $false $test_res $simple_test_res $warns, $fails
}
else {
    Write-Success "[PASS]"
}

# =============================================
# Get Routes
# =============================================

Write-Host "Getting routes [for technical users]..."

$net_route = Get-NetRoute

$test_res['net_route'] = $net_route
$simple_test_res['net_route'] = $net_route | Select-Object -Property DestinationPrefix, InterfaceAlias, InterfaceIndex, NextHop, RouteMetric

if ($display_routing_table) {
    Write-NonImportantDescription " Routes:"
    foreach ($route in $net_route) {
        Write-NonImportantTest "   - $($route.DestinationPrefix)"
        if ($null -ne $route.RouteMetric) {
            Write-NonImportantTest " [$($route.RouteMetric)]"
        }
        if (($route.AddressFamily -eq "IPv4" -and $route.NextHop -eq "0.0.0.0") -or ($route.AddressFamily -eq "IPv6" -and $route.NextHop -eq "::")) {
            Write-NonImportantTest " is directly connected, $($route.InterfaceAlias)"
        }
        else {
            Write-NonImportantTest " via $($route.NextHop), $($route.InterfaceAlias)"
        }
        Write-Host ""
    }
}

# =============================================
# Get DNS Servers
# =============================================

Write-Host -NoNewline "Getting interface DNS settings..."
Write-NonImportantDescription "[ONGOING]"

$iface_dns_test_res = @{};

foreach ($dns in $net_config | ForEach-Object DNSServer) {
    if ($null -ne $dns -and $dns.ServerAddresses.Count -gt 0 -and $up_net_adapters_indexes.Contains($dns.InterfaceIndex)) {
        $iface_dns_test_res[$dns.InterfaceAlias] = @{}
        Write-NonImportantDescription " - $($dns.InterfaceAlias) $($dns.SuffixOrigin)"
        foreach ($addr in $dns.ServerAddresses) {
            Write-NonImportantDescription "   - $($addr)"
            
            $iface_dns_test_res[$dns.InterfaceAlias][$addr] = @{}

            $ping_test_res = Test-PingReach $addr "     - "
            if ($ping_test_res.Count -eq 0) {
                $fails += "DNS Server, $($addr) not reply ICMP Echo request"
            }
            $iface_dns_test_res[$dns.InterfaceAlias][$addr]['~ping'] = $ping_test_res

            foreach ($dig_test_domain in $dig_test_domains) {
                Write-NonImportantTest "     - $($dig_test_domain)"

                $dig_res = Resolve-DnsName -Name $dig_test_domain -Server $addr -ErrorAction SilentlyContinue
                if ($null -ne $dig_res) {
                    Write-NonImportantSuccess " [PASS]"
                    $iface_dns_test_res[$dns.InterfaceAlias][$addr][$dig_test_domain] = $dig_res
                }
                else {
                    Write-NonImportantFail " [FAIL]"
                    $iface_dns_test_res[$dns.InterfaceAlias][$addr][$dig_test_domain] = $false
                }
            }
        }
    }
}

$test_res['iface_dns_result'] = $iface_dns_test_res
$simple_test_res['iface_dns_result'] = $iface_dns_test_res | Select-Object -Property Name, QueryType, Type, Section, TTL, IPAddress

# =============================================
# Test System DNS Server
# =============================================

$dns_grand_res = @{}

foreach ($dig_test_domain in $dig_test_domains) {
    Write-Host -NoNewline "Query to system dns "
    Write-Host -NoNewline "[$($dig_test_domain)]" -ForegroundColor DarkGray -BackgroundColor Black
    Write-Host -NoNewline "..."
    
    $grand_dns_test_res = Resolve-DnsName -Name $dig_test_domain -ErrorAction SilentlyContinue
    if ($null -ne $grand_dns_test_res) {
        $dns_grand_res[$dig_test_domain] = $grand_dns_test_res
        Write-Success "[PASS]"
    }
    else {
        Write-Fail "[FAIL]"
    }
}

Write-Host -NoNewline "Checking System DNS works..."

$test_res['sysdns_result'] = $dns_grand_res
$simple_test_res['sysdns_result'] = $dns_grand_res | Select-Object -Property Name, QueryType, Type, Section, TTL, IPAddress

if ($dns_grand_res.Count -eq 0) {
    Write-Fail "[FAIL]"
    $fails += "System prefered DNS wont work for test domain"
    End-Testing $false $test_res $simple_test_res $warns $fails
}
else {
    Write-Success "PASS"
}

# =============================================
# Test Ping reach
# =============================================

$ping_reach4 = @{}
$ping_reach6 = @{}

Write-Host -NoNewline "Sending ICMP Echo for v4 hosts..."
Write-NonImportantDescription "[ONGOING]"

$ping_reach4 = Test-PingReach $ping_destinations_v4

Write-Host -NoNewline "Sending ICMP Echo for v6 hosts..."
Write-NonImportantDescription "[ONGOING]"

$ping_reach6 = Test-PingReach $ping_destinations_v6

$test_res['ping_reach4'] = $ping_reach4
$test_res['ping_reach6'] = $ping_reach6
$simple_test_res['ping_reach4'] = $ping_reach4 | Select-Object -Property Address, IPV4Address, IPV6Address, ResponseTime, ResponseTimeToLive, StatusCode, BufferSize, TimeToLive, InterfaceAlias, InterfaceIndex
$simple_test_res['ping_reach6'] = $ping_reach6 | Select-Object -Property Address, IPV4Address, IPV6Address, ResponseTime, ResponseTimeToLive, StatusCode, BufferSize, TimeToLive, InterfaceAlias, InterfaceIndex

Write-Host -NoNewline "Checking ICMP Echo reply..."

if ($ping_reach6.Count -eq 0 -and $ping_reach4.Count -eq 0) {
    Write-Fail "[FAIL]"
    Write-NonImportantDescription "Some network restrict to send ICMP packets. Test continues."
    $fails += "No one returns ICMP echo reply [$($ping_reach6.Count)/$($ping_destinations_v6.Count) hosts return ICMP echo reply, $($ping_reach4.Count)/$($ping_destinations_v4.Count) hosts return ICMP echo reply]"
}
elseif ($ping_reach4.Count -eq 0) {
    Write-Warn "[WARN] All v4 hosts wont return ICMP echo reply"
    Write-NonImportantDescription "Some network restrict to send ICMP packets. Test continues."
    $warns += "All v4 hosts wont return ICMP echo reply [$($ping_reach4.Count)/$($ping_destinations_v4.Count) hosts return ICMP echo reply]"
    Write-IPv4OnlyFailNotice
}
elseif ($ping_reach6.Count -eq 0) {
    Write-Warn "[WARN] All v6 hosts wont return ICMP echo reply"
    Write-NonImportantDescription "Some network restrict to send ICMP packets. Test continues."
    $warns += "All v6 hosts wont return ICMP echo reply [$($ping_reach6.Count)/$($ping_destinations_v6.Count) hosts return ICMP echo reply]"
    Write-IPv6OnlyFailNotice
}
else {
    Write-Success "[PASS]"
}

# =============================================
# Proxy Settings
# =============================================

$this_env_has_proxy = $false

if ($PSVersionTable.PSVersion.Major -gt 5) {
    Write-Warn "[WARN] This script won't test Proxy on PowerShell 7.0 or later"
}
else {
    Write-Host -NoNewline "Checking proxy settings..."
    
    $proxy_conf = [System.Net.WebProxy]::GetDefaultProxy()
    $this_env_has_proxy = $null -ne $proxy_conf.Address
    
    $test_res['proxy_conf'] = $proxy_conf
    $simple_test_res['proxy_conf'] = $proxy_conf | Select-Object -Property Address, BypassList, BypassProxyOnLocal, UseDefaultCredentials
    
    if ($this_env_has_proxy) {
        Write-Success "[PASS]"
        Write-NonImportantDescription " $($proxy_conf.Address)"
    }
    else {
        Write-Success "[SKIP]"
        $warns += "No proxy is set. In almost cases, this is not a problem."
    }
}


# =============================================
# Proxy Test
# =============================================

if ($this_env_has_proxy) {
    Write-Host -NoNewline "Testing proxy server..."

    try {
        $proxy_direct_access = Invoke-WebRequest -Uri $proxy_conf.Address -Method GET -ErrorAction SilentlyContinue
        $proxy_status_code = $proxy_direct_access.StatusCode
    }
    catch {
        $proxy_status_code = $_.Exception.Response.StatusCode.value__
    }

    $test_res['proxy_status_code'] = $proxy_status_code
    $simple_test_res['proxy_status_code'] = $proxy_status_code

    if ($null -eq $proxy_status_code) {
        Write-Fail "[FAIL] Proxy server is not reachable"
        $fails += "Proxy server is not reachable [GET $($proxy_conf.Address) failed]"
        End-Testing $false $test_res $simple_test_res $warns $fails
    }
    else {
        Write-Success "[PASS] Proxy server is reachable"
    }
}

# =============================================
# HTTP Test
# =============================================

if ($this_env_has_proxy) {
    Write-Host -NoNewline "Testing HTTP connection..."
    Write-Fail "[FAIL] Proxy In Use"
    Write-NonImportantDescription " This script didn't support proxy environment now."
    $fails += "Proxy In Use"
}
else {
    Write-Host -NoNewline "Sending HTTP requests..."
    Write-NonImportantDescription "[ONGOING]"

    $http_test_success = 0;

    $test_res['http_status_code'] = @{}
    $simple_test_res['http_status_code'] = @{}

    foreach ($http_test_destination in $http_test_destinations) {
        Write-NonImportantTest " $($http_test_destination)..."

        try {
            $http_res = Invoke-WebRequest -Uri $http_test_destination -Method GET -ErrorAction SilentlyContinue
            $http_status_code = $http_res.StatusCode
        }
        catch {
            $http_status_code = $_.Exception.Response.StatusCode.value__
        }

        $test_res['http_status_code'][$http_test_destination] = $http_status_code
        $simple_test_res['http_status_code'][$http_test_destination] = $http_status_code

        if ($null -eq $http_status_code) {
            Write-Fail "[FAIL]"
            $fails += "$($http_test_destination) is not reachable [GET $($http_test_destination) failed]"
        }
        else {
            Write-Success "[PASS]"
            $http_test_success++
        }
    }

    Write-Host -NoNewline "Testing HTTP requests..."

    if ($http_test_success -eq 0) {
        Write-Fail "[FAIL]"
        $fails += "All HTTP destination is unreachable"
        End-Testing $false $test_res $simple_test_res $warns $fails
    }
    elseif ($http_test_success -lt $http_test_destinations.Count) {
        Write-Warn "[WARN] Some HTTP test destination unreachable"
        $warns += "Some HTTP destination is unreachable"
    }
    else {
        Write-Success "[PASS]"
    }
}


# =============================================
# HTTPS Test
# =============================================

if ($this_env_has_proxy) {
    Write-Host -NoNewline "Testing HTTPS connection..."
    Write-Fail "[FAIL] Proxy In Use"
    Write-NonImportantDescription " This script didn't support proxy environment now."
    $fails += "Proxy In Use"
}
else {
    Write-Host -NoNewline "Sending HTTPS requests..."
    Write-NonImportantDescription "[ONGOING]"

    $http_test_success = 0;

    $test_res['http_status_code'] = @{}
    $simple_test_res['http_status_code'] = @{}

    foreach ($http_test_destination in $https_test_destinations) {
        Write-NonImportantTest " $($http_test_destination)..."

        try {
            $http_res = Invoke-WebRequest -Uri $http_test_destination -Method GET -ErrorAction SilentlyContinue
            $http_status_code = $http_res.StatusCode
        }
        catch {
            $http_status_code = $_.Exception.Response.StatusCode.value__
        }

        $test_res['http_status_code'][$http_test_destination] = $http_status_code
        $simple_test_res['http_status_code'][$http_test_destination] = $http_status_code

        if ($null -eq $http_status_code) {
            Write-Fail "[FAIL]"
            $fails += "$($http_test_destination) is not reachable [GET $($http_test_destination) failed]"
        }
        else {
            Write-Success "[PASS]"
            $http_test_success++
        }
    }

    Write-Host -NoNewline "Testing HTTPS requests..."

    if ($http_test_success -eq 0) {
        Write-Fail "[FAIL]"
        $fails += "All HTTPS destination is unreachable"
        End-Testing $false $test_res $simple_test_res $warns $fails
    }
    elseif ($http_test_success -lt $http_test_destinations.Count) {
        Write-Warn "[WARN] Some HTTPS test destination unreachable"
        $warns += "Some HTTPS destination is unreachable"
    }
    else {
        Write-Success "[PASS]"
    }
}

# =============================================
# Test QUIC Connectivity
# =============================================

if ($PSVersionTable.PSVersion.Major -gt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -ge 4)) {
    $http_client_for_quic_test = [System.Net.Http.HttpClient]::new()
    $http_client_for_quic_test.DefaultRequestVersion = [System.Net.HttpVersion]::Version30
    $http_client_for_quic_test.DefaultVersionPolicy = [System.Net.Http.HttpVersionPolicy]::RequestVersionExact
    
    $quic_test_res = @{}
    
    try {
        Write-Host -NoNewline "Testing QUIC connectivity..."
        Write-NonImportantDescription "[ONGOING]"
    
        foreach ($https_quic_test_destination in $https_quic_test_destinations) {
            Write-NonImportantTest " $($https_quic_test_destination) "
    
            try {
                $quic_res = $http_client_for_quic_test.GetStringAsync($https_quic_test_destination).GetAwaiter().GetResult()
                $quic_res_len = $quic_res.Length
                Write-NonImportantSuccess "[PASS] ($($quic_res_len) bytes)"
                $quic_test_res[$https_quic_test_destination] = $quic_res_len
            }
            catch {
                Write-NonImportantFail "[FAIL]"
                $fails += "$($https_quic_test_destination) is not return QUIC response"
            }
        }
    }
    catch {
        Write-Fail "[EMRG] QUIC Test Unexpected Error"
        $fails += "[EMRG] QUIC Test Unexpected Error [$_]"
    }
    finally {
        $http_client_for_quic_test.Dispose()
    }
    
    
    Write-Host -NoNewline "Testing QUIC response..."
    
    if ($quic_test_res.Count -eq 0) {
        Write-Fail "[FAIL]"
        $fails += "All QUIC destination is unreachable"
        Write-Warn "Some network restrict to use QUIC. Test continues."
    }
    else {
        Write-Success "[PASS]"
    }

    $test_res['quic_test_res'] = $quic_test_res
    $simple_test_res['quic_test_res'] = $quic_test_res
}
else {
    Write-Warn "[WARN] This script won't test QUIC on PowerShell 7.3 or earlier"
}


# =============================================
# Test ending
# =============================================

End-Testing $true $test_res $simple_test_res $warns $fails