<#
 .SYNOPSIS
    Set Certificate Authority Extensions

 .DESCRIPTION
    Connect to CA and set extensions for pending request

 .EXAMPLE
    Get Key Usage enum
    $KEY_USAGE = Set-CAExtension -GetKeyUsage

    Set Key Usage for Digital Signature and Key Encipherment
    Set-CAExtension -RequestId <ID> -KeyUsage @($KEY_USAGE::DIGITAL_SIGNATURE, $KEY_USAGE::KEY_ENCIPHERMENT)

    Get Alt Name enum
    $ALT_NAME = Set-CAExtension -GetAltName

    Set Subject Alternative Names
    Set-CAExtension -RequestId <ID> -SubjectAlternativeNames @{ $ALT_NAME::DNS_NAME = 'fqdn' }

    Set Basic Constraint Subject Type = CA and Path Length = None
    Set-CAExtension -RequestId <ID> -SubjectType CA -PathLength -1

 .NOTES
    Debug:
    [Convert]::FromBase64String($X509Ext.RawData(1))

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

function Set-CAExtension
{
    [cmdletbinding(DefaultParameterSetName='Set')]

    Param
    (
        [Parameter(ParameterSetName='Set', Mandatory=$true)]
        [String]$RequestId,

        [Parameter(ParameterSetName='Set')]
        [Array]$KeyUsage,

        [Parameter(ParameterSetName='GetKeyUsage')]
        [Switch]$GetKeyUsage,

        [Parameter(ParameterSetName='Set')]
        [ValidateSet('CA', 'EndEntity')]
        [String]$SubjectType,

        [Parameter(ParameterSetName='Set')]
        [String]$PathLength,

        [Parameter(ParameterSetName='Set')]
        [Hashtable]$SubjectAlternativeNames,

        [Parameter(ParameterSetName='GetAltName')]
        [Switch]$GetAltName,

        [String]$Config
    )

    Begin
    {
        ########
        # Enums
        ########

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertconfig-getconfig
        enum CC_CONFIG
        {
            DEFAULT           = 0x0
            UIPICK            = 0x1
            FIRST             = 0x2
            LOCAL             = 0x3
            LOCALACTIVE       = 0x4
            UIPICKSKIPLOCALCA = 0x5
        }

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/8116912a-59e6-4849-83dd-77b39b6370e0
        enum PROPTYPE
        {
            LONG     = 0x1
            DATETIME = 0x2
            BINARY   = 0x3
            STRING   = 0x4
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certif/nf-certif-icertserverexit-getcertificateextensionflags
        enum POLICY
        {
            NON_CRITICAL = 0x0
            CRITICAL     = 0x1
            DISABLE      = 0x2
        }

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

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-alternativenametype
        enum ALT_NAME
        {
            UNKNOWN             = 0x0
            OTHER_NAME          = 0x1
            RFC822_NAME         = 0x2
            DNS_NAME            = 0x3
            X400_ADDRESS        = 0x4
            DIRECTORY_NAME      = 0x5
            EDI_PARTY_NAME      = 0x6
            URL                 = 0x7
            IP_ADDRESS          = 0x8
            REGISTERED_ID       = 0x9
            GUID                = 0x10
            USER_PRINCIPLE_NAME = 0x11
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

        #######################
        # Get ParameterSetName
        #######################

        $ParameterSetName = $PsCmdlet.ParameterSetName

        ###################
        # Get local config
        ###################

        if (-not $Config)
        {
            # Get config
            $CA = New-Object -ComObject CertificateAuthority.GetConfig
            $Config = $CA.GetConfig([CC_CONFIG]::LOCAL)

            if (-not $Config)
            {
                throw "Can't find local certificate authority, please use -Config parameter."
            }
        }
    }

    Process
    {
        if ($ParameterSetName -eq 'Set')
        {
            $Extensions = @()

            ############
            # Key usage
            # 2.5.29.15
            ############

            if ($KeyUsage -and $KeyUsage.Count -gt 0)
            {
                foreach ($Flag in $KeyUsage)
                {
                    $KeyUsageFlags += [KEY_USAGE]::$Flag
                }

                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage

                # Initialize
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionkeyusage-initializeencode
                $X509Ext.InitializeEncode($KeyUsageFlags)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.15'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

            ############################
            # Subject Alternative Names
            # 2.5.29.17
            ############################

            if ($SubjectAlternativeNames -and $SubjectAlternativeNames.Count -gt 0)
            {
                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames

                # Create alternative name collection
                $AlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

                foreach ($Pair in $SubjectAlternativeNames.GetEnumerator()) {

                    # Create alternative name
                    $AlternativeName = New-Object -ComObject X509Enrollment.CAlternativeName

                    try
                    {
                        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ialternativename-initializefromstring
                        $AlternativeName.InitializeFromString([ALT_NAME]::$($Pair.Name), $Pair.Value)
                    }
                    catch [Exception]
                    {
                        throw $_
                    }

                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ialternativenames-add
                    $AlternativeNames.Add($AlternativeName)
                }

                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionalternativenames-initializeencode
                $X509Ext.InitializeEncode($AlternativeNames)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.17'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::NON_CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

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

                if ($PathLength -like $null)
                {
                    $PathLength = -1
                }

                # Create new object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

                # Initialize
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionbasicconstraints-initializeencode
                $X509Ext.InitializeEncode($IsCA, $PathLength)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.19'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
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
                    $CaAdmin.SetCertificateExtension(
                        $Config,
                        $RequestID,
                        $Ext['strExtensionName'],
                        $Ext['Type'],
                        $Ext['Flags'],
                        $Ext['pvarValue']
                    )
                }
            }
        }
        elseif ($GetKeyUsage.IsPresent)
        {
            Write-Output -InputObject ([KEY_USAGE])
        }
        elseif ($GetAltName.IsPresent)
        {
            Write-Output -InputObject ([ALT_NAME])
        }
    }

    End
    {
        Remove-Variable -Name CaAdmin, X509*, AlternativeName* -ErrorAction SilentlyContinue
    }
}


# SIG # Begin signature block
# MIIY9AYJKoZIhvcNAQcCoIIY5TCCGOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxm1/GD6UZS5MCAT4dOafQcz9
# RCOgghJ3MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUUQdc
# 9PGn9JpczaukJikc9UCLMrgwDQYJKoZIhvcNAQEBBQAEggIAe1G13GIdh7HjiCYK
# HnNDe4vLvA52DWfAfepCwDxZ2hoa76iknHo0O004PtWJhxJtc3oL3w/XcRHLLTyu
# qwJoqRsEQEuxHMwjB7XjnQvWLKf3rjM4SRhMqPheVyO0w7c1wQHkDw2ISFKwQG6u
# iiQS8eeIrRHnGoirXYHQBKT8SclZ4q6eeInHmE/TVILl2bveVypYWUqjKS9gIgAF
# 3mbJkDkVepUFuzric2uhSZv/L2YVxZ2ZSVGnNc8+DVvr7SR53Wd/l074gH2W25MB
# SjVrq/CFKIk8MrITqze2m5+yXyKrz4B9/+LGzdfmJxHEp/+unpLVB7InZV3bKgwz
# g8XUpdSHsSlh/fsmkdiE4XMCaoPzZtOvZZB1X5jKpqa/jNw/h6vOsImt+hxm445G
# 09tm6nktO8n942UFWkNF4HwP7h1+tOUHSBweEksUSwizaHrEKdJeN4p+8vMCR3Qy
# Ktl9/F80KiqZtiL29b3orBviOBG9fQPyaCqEqONuw67vkvn4OulC00yOzs9OSt7b
# EC1K8+Sc3yCNYXQb+wntYLjBkBVK+Qee5y9tws5y6F3VQbeThScY1fItOdYRc6dv
# LwKZ8705VgL8xPYULx5bJgy9NCkd+rqjBxlPZ0y0YXzzEvAUrjjqAPQEm3sBsm+Y
# ldowgSNa9QFmbHb5faQAZp/qVAyhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNDI3MTQw
# MDA0WjAvBgkqhkiG9w0BCQQxIgQgR529w94gaIO9DvJbwDyPMhCXsribZhbE/7kn
# wi/4My8wDQYJKoZIhvcNAQEBBQAEggIAQ0BLarO8KFQOkyddbKa2/SPIEG57fw4M
# K4n3rS8qRXVnOOcm3N8lAv15qjh2TYF8GWEsiBzxDeugeM8IXHZBcbEBAcU+wSJ4
# uHvTVlu8bAYfLawsQmsqOphF/gnGuAxAG+CFseCirTXFL5bGcZudjCdj1tTASW6O
# jtJUmmCJlhEmb9aVhe2kTFDYyIrKBhcIOAcoizYUlrX209cB24dLXjIB6Gey0f2g
# RdVlM1Vy5VqwZLXaOoSJQC3BzlWl7TNlwbCCH0Dvdkq1iZ38VTVjT78I2XuYbazz
# bOSqKizFaE92PeR5goyH70Z/hVr8uV+H8JNRFh1lGVk0zUdhtmJMHfEggVcrb9Kl
# 5olNsR+fOEDmhDcZQvEBMlFCCySDP9N7IeSgQpFoTMvTBG6nPsZQoAd/6+F8Oo7y
# wQZfasLgxobPrnJzK+qDn5q7f1JE2MJ1DHwyXYSTXTT6v4yh9YTQ7r1OlKA3Z2Qp
# K1QQQYordCNziMh5qeyW+ce4oL2lWVOCcZe/0pEB1bCP1dAbEFBYlJn9BWXzt4cy
# iW1mnyibfI/rnGKxAjc1eUU/jI0d5MFhYVsoD9p6TO6U5gGXU2neesr2uSDPeWlq
# tA7vLxOo1Od/idrBgxhBQH6hxqaCSLaC23XwzV5L+ouJyXK3f+G9WGfobNp2t0A5
# 5AucqZDZ64s=
# SIG # End signature block
