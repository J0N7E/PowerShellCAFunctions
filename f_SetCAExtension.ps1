<#
 .SYNOPSIS
    Set Certificate Authority Extension

 .DESCRIPTION
    Connect to CA and set extension for pending request

 .EXAMPLE
    Set key usage for digital signature and key encipherment
    Set-CAExtension -RequestId <ID> -KeyUsage @([KEY_USAGE]::DIGITAL_SIGNATURE, [KEY_USAGE]::KEY_ENCIPHERMENT)

    Set basic constraint Subject Type = ca and Path Length = None
    Set-CAExtension -RequestId <ID> -SubjectType CA -PathLength -1

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

function Set-CAExtension
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$RequestId,

        [Array]$KeyUsage,

        [ValidateSet('CA', 'EndEntity')]
        [String]$SubjectType,

        [Int]$PathLength,

        [String]$Config
    )

    Begin
    {
        ########
        # Enums
        ########

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertconfig-getconfig
        enum CC
        {
            DEFAULTCONFIG           = 0x00000000
            UIPICKCONFIG            = 0x00000001
            FIRSTCONFIG             = 0x00000002
            LOCALCONFIG             = 0x00000003
            LOCALACTIVECONFIG       = 0x00000004
            UIPICKCONFIGSKIPLOCALCA = 0x00000005
        }

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/7c715f9f-db50-41c3-abfc-0021c6390d4e
        enum PROPTYPE
        {
            LONG     = 0x00000001
            DATETIME = 0x00000002
            BINARY   = 0x00000003
            STRING   = 0x00000004
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certif/nf-certif-icertserverexit-getcertificateextensionflags
        enum EXTENSION
        {
            CRITICAL_FLAG = 0x1
            DISABLE_FLAG  = 0x2
        }

        ############
        # Functions
        ############

        function ConvertTo-DERstring ([byte[]]$Bytes)
        {
            if ($Bytes.Length % 2 -eq 1)
            {
                $Bytes += 0
            }

            $String = New-Object System.Text.StringBuilder

            for ($n = 0; $n -lt $Bytes.Count; $n += 2)
            {
                $String.Append([char]([int]$Bytes[$n + 1] -shl 8 -bor $Bytes[$n])) > $null
            }

            Write-Output -InputObject $String.ToString()
        }

        ###############
        # Check Config
        ###############

        if (-not $Config)
        {
            # Get config
            $CA = New-Object -ComObject CertificateAuthority.GetConfig
            $Config = $CA.GetConfig([CC]::LOCALCONFIG)

            if (-not $Config)
            {
                throw "Can't find certificate authority config string, please use -CAConfig parameter."
            }
        }
    }

    Process
    {
        $Extensions = @()

        ####################
        # Basic Constraints
        # 2.5.29.19
        ####################

        if ($SubjectType -or $PathLength)
        {
            $IsCA = $false

            if ($SubjectType -eq 'CA')
            {
                $IsCA = $true
            }

            if (-not $PathLength)
            {
                $PathLength = -1
            }

            # Create new object
            $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

            # Initialize
            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionbasicconstraints-initializeencode
            # Debug:
            # [Convert]::FromBase64String($X509Ext.RawData(1))
            $X509Ext.InitializeEncode($IsCA, $PathLength)

            # Add to extensions
            $Extensions +=
            (@{
                'strExtensionName' = '2.5.29.19'
                'Type' = [PROPTYPE]::BINARY
                'Flags' = [EXTENSION]::CRITICAL_FLAG
                'pvarValue' = (ConvertTo-DERstring -Bytes ([Convert]::FromBase64String($X509Ext.RawData(1))))
            })
        }

        ############
        # Key usage
        # 2.5.29.15
        ############

        if ($KeyUsage -and $KeyUsage.Count -gt 0)
        {
            #######
            # Enum
            #######

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379410.aspx
            enum KEY_USAGE
            {
                NO                 = 0
                DIGITAL_SIGNATURE  = 0x80
                NON_REPUDIATION    = 0x40
                KEY_ENCIPHERMENT   = 0x20
                DATA_ENCIPHERMENT  = 0x10
                KEY_AGREEMENT      = 0x8
                KEY_CERT_SIGN      = 0x4
                OFFLINE_CRL_SIGN   = 0x2
                CRL_SIGN           = 0x2
                ENCIPHER_ONLY      = 0x1
                DECIPHER_ONLY      = 0x8000
            }

            foreach ($Flag in $KeyUsage)
            {
                $KeyUsageFlags += [KEY_USAGE]::$Flag
            }

            # Create new objecta
            $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage

            # Initialize
            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionkeyusage-initializeencode
            $X509Ext.InitializeEncode($KeyUsageFlags)

            # Add to extensions
            $Extensions +=
            (@{
                'strExtensionName' = '2.5.29.15'
                'Type' = [PROPTYPE]::BINARY
                'Flags' = [EXTENSION]::CRITICAL_FLAG
                'pvarValue' = (ConvertTo-DERstring -Bytes ([Convert]::FromBase64String($X509Ext.RawData(1))))
            })
        }

        ######
        # Set
        ######

        if ($Extensions.Count -gt 0)
        {
            $CaAdmin = New-Object -ComObject CertificateAuthority.Admin

            # Itterate extensions
            foreach($Ext in $Extensions)
            {
                # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-setcertificateextension
                $CaAdmin.SetCertificateExtension($Config, $RequestID, $Ext['strExtensionName'], $Ext['Type'], $Ext['Flags'], $Ext['pvarValue'])
            }
        }
    }

    End
    {
        Remove-Variable -Name CaAdmin, X509* -ErrorAction SilentlyContinue
    }
}


# SIG # Begin signature block
# MIIY9AYJKoZIhvcNAQcCoIIY5TCCGOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6q8dTODSxeVPchemB1o8nh8g
# 7LGgghJ3MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
# AQsFADAOMQwwCgYDVQQDDANiY2wwHhcNMjAwNDI5MTAxNzQyWhcNMjIwNDI5MTAy
# NzQyWjAOMQwwCgYDVQQDDANiY2wwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCu0nvdXjc0a+1YJecl8W1I5ev5e9658C2wjHxS0EYdYv96MSRqzR10cY88
# tZNzCynt911KhzEzbiVoGnmFO7x+JlHXMaPtlHTQtu1LJwC3o2QLAew7cy9vsOvS
# vSLVv2DyZqBsy1O7H07z3z873CAsDk6VlhfiB6bnu/QQM27K7WkGK23AHGTbPCO9
# exgfooBKPC1nGr0qPrTdHpAysJKL4CneI9P+sQBNHhx5YalmhVHr0yNeJhW92X43
# WE4IfxNPwLNRMJgLF+SNHLxNByhsszTBgebdkPA4nLRJZn8c32BQQJ5k3QTUMrnk
# 3wTDCuHRAWIp/uWStbKIgVvuMF2DixkBJkXPP1OZjegu6ceMdJ13sl6HoDDFDrwx
# 93PfUoiK7UtffyObRt2DP4TbiD89BldjxwJR1hakJyVCxvOgbelHHM+kjmBi/VgX
# Iw7UDIKmxZrnHpBrB7I147k2lGUN4Q+Uphrjq8fUOM63d9Vb9iTRJZvR7RQrPuXq
# iWlyFKcSpqOS7apgEqOnKR6tV3w/q8SPx98FuhTLi4hZak8u3oIypo4eOHMC5zqc
# 3WxxHHHUbmn/624oJ/RVJ1/JY5EZhKNd+mKtP3LTly7gQr0GgmpIGXmzzvxosiAa
# yUxlSRAV9b3RwE6BoT1wneBAF7s/QaStx1HnOvmJ6mMQrmi0aQIDAQABo1EwTzAO
# BgNVHQ8BAf8EBAMCBaAwHgYDVR0lBBcwFQYIKwYBBQUHAwMGCSsGAQQBgjdQATAd
# BgNVHQ4EFgQUEOwHbWEJldZG1P09yIHEvoP0S2gwDQYJKoZIhvcNAQELBQADggIB
# AC3CGQIHlHpmA6kAHdagusuMfyzK3lRTXRZBqMB+lggqBPrkTFmbtP1R/z6tV3Kc
# bOpRg1OZMd6WJfD8xm88acLUQHvroyDKGMSDOsCQ8Mps45bL54H+8IKK8bwfPfh4
# O+ivHwyQIfj0A44L+Q6Bmb+I0wcg+wzbtMmDKcGzq/SNqhYUEzIDo9NbVyKk9s0C
# hlV3h+N9x2SZJvZR1MmFmSf8tVCgePXMAdwPDL7Fg7np+1lZIuKu1ezG7mL8ULBn
# 81SFUn6cuOTmHm/xqZrDq1urKbauXlnUr+TwpZP9tCuihwJxLaO9mcLnKiEf+2vc
# RQYLkxk5gyUXDkP4k85qvZjc7zBFj9Ptsd2c1SMakCz3EWP8b56iIgnKhyRUVDSm
# o2bNz7MiEjp3ccwV/pMr8ub7OSqHKPSjtWW0Ccw/5egs2mfnAyO1ERWdtrycqEnJ
# CgSBtUtsXUn3rAubGJo1Q5KuonpihDyxeMl8yuvpcoYQ6v1jPG3SAPbVcS5POkHt
# DjktB0iDzFZI5v4nSl8J8wgt9uNNL3cSAoJbMhx92BfyBXTfvhB4qo862a9b1yfZ
# S4rbeyBSt3694/xt2SPhN4Sw36JD99Z68VnX7dFqaruhpyPzjGNjU/ma1n7Qdrnp
# u5VPaG2W3eV3Ay67nBLvifkIP9Y1KTF5JS+wzJoYKvZ2MIIGrjCCBJagAwIBAgIQ
# BzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAw
# MDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5
# NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYR
# oUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CE
# iiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCH
# RgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5K
# fc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDni
# pUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2
# nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp
# 88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1C
# vwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+
# 0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl2
# 7KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOC
# AV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaa
# L3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcw
# AoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+
# ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvX
# bYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tP
# iix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCy
# Xen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpF
# yd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3
# fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t
# 5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejx
# mF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxah
# ZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAA
# zV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vup
# L0QVSucTDh3bNzgaoSv27dZ8/DCCBsYwggSuoAMCAQICEAp6SoieyZlCkAZjOE2G
# l50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYg
# U0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBaFw0zMzAzMTQy
# MzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEk
# MCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7MXGzj4CUu0jHk
# PECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumjS0joiUF/DbLW
# +YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD0Z/NCcW5QWpF
# QiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De1FksRHTAMkcZ
# W+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D7n+FAsmG4dUY
# FLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/KC7CnuALS8gI
# 0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+X7Aa3Rm9n3RB
# Cq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DNkdcvnfv8zbHB
# p8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr5BSyFtaBocra
# MJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV6J67m0uy4rZB
# Peevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIspQnL3ebLdhOon
# 7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNV
# HQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5
# NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEADS0j
# dKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d5YZPvpM63io5
# WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC6kx2yqHcoSuW
# uJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8RyTFKWLbfOHzL
# +lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bemh2RPPkaJFmMg
# a8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkwNuTzqmkJqIt+
# ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+VG1/calIGnjd
# RncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGukzp123qlzqkhq
# WUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTmtQyimaXXFWs1
# DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qXsdhH6hyF4EVO
# EhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvTnMxttQ2uR2M4
# RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwxggXnMIIF4wIBATAiMA4xDDAK
# BgNVBAMMA2JjbAIQJoAlxDS3d7xJEXeERSQIkTAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU7o2Q
# d8cTkse2iRJ6/jhYXB8HHUswDQYJKoZIhvcNAQEBBQAEggIAon0ix+Em0HLwYOP4
# yrOSJXSjlppZg6hfQFyBOUz98dwe9+CyHkQmx+YwFycIEFS21vEcRI5dXT1S2JQ7
# HP2VL9iLW3g+lnZKFNfE7LagU6p3avxcEiG/75BxfSVoHu3+Np7NuhGDIfyAgv47
# D7ebxYaGRupS83TCnDfTd71zCeLsUBKFD61KUwCeNhkaQKioiU3kHHxMmJpTgdZi
# pXfU91xgEN7Ul1J/vl+lfZ2BcKew3duSuPrt222fY9zVtPtIZ0jSjKcSR9kq8bHX
# nuAzVb8JJne24cJJiTard1T8MtYgHJPobIhRbM1ArjQncHz8DAtpWv9ry2yDeYBL
# gs+IGEFTyn3CvkQGtrDVOCaN+I1nLleuOA6+WLaTSove4g/AbW9ukmAq4+TXEzI5
# Ih4YN702gbWJ6K/C0qu9zRFYApZOOWYP5M5PbDRqiFrx3wBr5LJ7cRqq2Sofw/+O
# WwBPKoAiT1/8YpdxvfIeceM9ERr7rbSzOPKROHcTv8/tD++I+X5WGCe40UfUB1ss
# OqO17yRh0r3JwG0tEIuIfAUG3KdCFGzgTnmw+mEy0Bx1UhWazgYAZK2PY2wdT+8C
# xNBO1xjjqFr69sL44YnAcs3y89TS7QMgggSFldmI7Z68T+XkgdQx+mc4NV83e/Zu
# Zal0RYLa/epaaxYH7u861Pk5s4yhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNDI1MTM0
# OTEyWjAvBgkqhkiG9w0BCQQxIgQgnsrbDnpa2uVBVrGChlxpOTS23bgfIbwf0fnC
# 7ko2+kwwDQYJKoZIhvcNAQEBBQAEggIAKSTaQGhuq/M9YSsuhvHAd/8g+m5ypqcL
# IQgyEbciOMbm/d/3FTP8LaEWrNw4hv1E/YLzZAQo2gDUa0TrKdbDfMXhiVL2sjiC
# 8Ibe3aBSPyV03nPXw0OZG3A1V9iOTIsNshkXecii3BVBSantTh0tDCaO0QPvRYMU
# 6bWTD9WrWpQHjtrzcNHdqQAe7GC40b2Y6+pN0FKgwlEa9kzNw7r7UJinjxrUDOOr
# 1L5dUdsHfmiFU/c8FtKHvaZ3oZGzWfJLu/3rbcCS1V5O6XS4xgkZhBnRYzrQkzQQ
# +P+iIELodNV9vgCKAQOW6TlO8T1Wee5g/0niS5xi5JBJZ9CzJTHcd/22BHwBUOLY
# K1sx5m7O1HroZ1kQnWTVYnv2csbo86NHXgAXeIOZ3IIM24hOdcutXi4DwtHtIovQ
# 6poJEjBp/wgQKOR8rjAgWho1fceQinKcHYbI92zyPuHjVddZYAGRgqNH9carvqTU
# Z6qmjP4M85VDdRpILdxuvIW1/uE0R8ocDy756CFUEqU6SuXw0GchKSRlW88XIDCl
# txhLnOYsWNdOzherYyy15tlQejZU8o9oqL5DNa9sbw+gwa2tfcTV78pgoXSaA3HM
# nBX3d/5xTD0i9wzAYZxqmuMUGcz4BNG1g7OtqD1t0Pje8nB66YZcMcDeJRYsUTu9
# y+A3SfwIh3Q=
# SIG # End signature block
