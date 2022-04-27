<#
 .SYNOPSIS
    Get Certificate Authority View

 .DESCRIPTION
    Connect to CA and show database content from different tables

 .EXAMPLE
    Get all requests
    Get-CAView -Request

    Get pending requests
    Get-CAView -Request -Status Pending

    Get request with specific RequestId
    Get-CAView -Request -RequestId <ID>

    Get request with specific Template OID
    Get-CAView -Request -Template <OID>

    Get all extensions for specific RequestId
    Get-CAView -Extension -RequestId <ID>

    Get specific extension for specific RequestId
    Get-CAView -Extension -Name <extension> -RequestId <ID>

    Get request table schema
    Get-CAView -Request -GetSchema

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

function Get-CAView
{
    [cmdletbinding(DefaultParameterSetName='Request')]

    Param
    (
        [Parameter(ParameterSetName='Request', Mandatory=$true)]
        [Parameter(ParameterSetName='Request_Schema', Mandatory=$true)]
        [Switch]$Request,

        [Parameter(ParameterSetName='Request')]
        [ValidateSet('Issued', 'Pending', 'Failed', 'Revoked')]
        [String]$Status,

        [Parameter(ParameterSetName='Request')]
        [String]$Template,

        [Parameter(ParameterSetName='Extension', Mandatory=$true)]
        [Parameter(ParameterSetName='Extension_Schema', Mandatory=$true)]
        [Switch]$Extension,

        [Parameter(ParameterSetName='Extension')]
        [ArgumentCompleter({

            $Extensions =
            @{
                "'SMIME Capabilities'"                = '1.2.840.113549.1.9.15'
                "'Certificate Type'"                  = '1.3.6.1.4.1.311.20.2'
                "'CA Version'"                        = '1.3.6.1.4.1.311.21.1'
                "'Certificate Template Information'"  = '1.3.6.1.4.1.311.21.7'
                "'Application Policies'"              = '1.3.6.1.4.1.311.21.10'
                "'Authority Information Access'"      = '1.3.6.1.5.5.7.1.1'
                "'OCSP No Revocation Checking'"       = '1.3.6.1.5.5.7.48.1.5'
                "'Subject Key Identifier'"            = '2.5.29.14'
                "'Key Usage'"                         = '2.5.29.15'
                "'Subject Alternative Name'"          = '2.5.29.17'
                "'Basic Constraints'"                 = '2.5.29.19'
                "'CRL Distribution Points'"           = '2.5.29.31'
                "'Certificate Policies'"              = '2.5.29.32'
                "'Authority Key Identifier'"          = '2.5.29.35'
                "'Enhanced Key Usage'"                = '2.5.29.37'
            }

            if ($args[4].GetHashtable)
            {
                $Extensions
            }
            else
            {
                $Extensions.Keys
            }
        })]
        [String]$Name,

        [Parameter(ParameterSetName='Request')]
        [Parameter(ParameterSetName='Extension')]
        [String]$RequestId,

        [Parameter(ParameterSetName='Attribute', Mandatory=$true)]
        [Parameter(ParameterSetName='Attribute_Schema', Mandatory=$true)]
        [Switch]$Attribute,

        [Parameter(ParameterSetName='Crl', Mandatory=$true)]
        [Parameter(ParameterSetName='Crl_Schema', Mandatory=$true)]
        [Switch]$Crl,

        [Parameter(ParameterSetName='Request_Schema', Mandatory=$true)]
        [Parameter(ParameterSetName='Extension_Schema', Mandatory=$true)]
        [Parameter(ParameterSetName='Attribute_Schema', Mandatory=$true)]
        [Parameter(ParameterSetName='Crl_Schema', Mandatory=$true)]
        [Switch]$GetSchema,

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

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview-setrestriction
        enum CV_COLUMN
        {
            QUEUE         = -1 # Pending
            LOG_DEFAULT   = -2 # Issued, failed & revoked
            LOG_FAILED    = -3
            LOG_REVOKED   = -7
        }

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/8116912a-59e6-4849-83dd-77b39b6370e0
        enum PROPTYPE
        {
            LONG     = 0x1
            DATETIME = 0x2
            BINARY   = 0x3
            STRING   = 0x4
        }

        enum CVR_SEEK
        {
            EQ = 0x1
            LE = 0x2
            LT = 0x4
            GE = 0x8
            GT = 0x10
        }

        enum CVRC_TABLE
        {
            REQUESTS   = 0X0
            EXTENSIONS = 0X3
            ATTRIBUTES = 0X4
            CRL        = 0X5
        }

        enum Disposition
        {
            Active             = 8
            Pending            = 9
            CACertificate      = 15
            CACertificateChain = 16
            Issued             = 20
            Revoked            = 21
            Failed             = 30
            Denied             = 31
        }

        ############
        # Set table
        ############

        if ($Request.IsPresent)
        {
            $Table = 'Request'
        }
        elseif ($Extension.IsPresent)
        {
            $Table = 'Extension'
        }
        elseif ($Attribute.IsPresent)
        {
            $Table = 'Attribute'
        }
        elseif ($Crl.IsPresent)
        {
            $Table = 'Crl'
        }

        #############
        # Extensions
        #############

        # Get extensions from argumentcompleter scriptblock
        $Extensions = Invoke-Command -ScriptBlock $MyInvocation.MyCommand.Parameters.Item("Name").Attributes.ScriptBlock `
                                     -ArgumentList @($null, $null, $null, $null, @{ GetHashTable = $True })

        ###################
        # Get local config
        ###################

        if (-not $Config)
        {
            # Get CA config
            $CA = New-Object -ComObject CertificateAuthority.GetConfig
            $Config = $CA.GetConfig([CC_CONFIG]::LOCAL)

            if (-not $Config)
            {
                throw "Can't find local certificate authority, please use -Config parameter."
            }
        }

        ##########
        # Connect
        ##########

        try
        {
            $CaView = New-Object -ComObject CertificateAuthority.View
            $CaView.OpenConnection($Config)
        }
        catch [Exception]
        {
            throw $_
        }
    }

    Process
    {
        if ($Table)
        {
            switch ($Table)
            {
                'Request'
                {
                    $CaView.SetTable([CVRC_TABLE]::REQUESTS)

                    ###################
                    # Set restrictions
                    ###################

                    switch($Status)
                    {
                        'Issued'
                        {
                            $CaView.SetRestriction(
                                $CaView.GetColumnIndex(0, 'Disposition'),
                                [CVR_SEEK]::EQ,
                                0,
                                [Disposition]::Issued
                            )

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'CommonName',
                                'NotBefore',
                                'NotAfter',
                                'CertificateTemplate',
                                'SerialNumber',
                                'CertificateHash'
                            )
                        }

                        'Pending'
                        {
                            $CaView.SetRestriction([CV_COLUMN]::QUEUE, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'Request.CommonName',
                                'Request.SubmittedWhen',
                                'CertificateTemplate'
                            )
                        }

                        'Failed'
                        {
                            $CaView.SetRestriction([CV_COLUMN]::LOG_FAILED, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'Request.CommonName',
                                'Request.SubmittedWhen',
                                'Request.StatusCode',
                                'Request.DispositionMessage',
                                'CertificateTemplate'
                            )
                        }

                        'Revoked'
                        {
                            $CaView.SetRestriction(
                                $CaView.GetColumnIndex(0, 'Disposition'),
                                [CVR_SEEK]::EQ,
                                0,
                                [Disposition]::Revoked
                            )

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.CommonName',
                                'Request.RevokedWhen',
                                'Request.RevokedReason',
                                'SerialNumber',
                                'CertificateHash'
                            )
                        }

                        default
                        {
                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'Request.CommonName',
                                'CertificateTemplate'
                            )
                        }
                    }

                    if ($RequestId)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"Request.RequestID"),
                            [CVR_SEEK]::EQ,
                            0,
                            [int]$RequestId
                        )
                    }

                    if ($Template)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"CertificateTemplate"),
                            [CVR_SEEK]::EQ,
                            0,
                            $Template
                        )
                    }
                }

                'Extension'
                {
                    $CaView.SetTable([CVRC_TABLE]::EXTENSIONS)

                    if ($Name)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"ExtensionName"),
                            [CVR_SEEK]::EQ,
                            0,
                            $Extensions["'$Name'"]
                        )
                    }

                    if ($RequestId)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"ExtensionRequestId"),
                            [CVR_SEEK]::EQ,
                            0,
                            [int]$RequestId
                        )
                    }

                    $ResultColumns =
                    (
                        "ExtensionRequestId",
                        "ExtensionName",
                        "ExtensionRawValue",
                        "ExtensionFlags"
                    )
                }

                'Attribute'
                {
                    if (-not $GetSchema.IsPresent)
                    {
                        throw [System.Management.Automation.PSNotImplementedException] "Not implemented."
                    }
                }

                'Crl'
                {
                    if (-not $GetSchema.IsPresent)
                    {
                        throw [System.Management.Automation.PSNotImplementedException] "Not implemented."
                    }
                }
            }

            #####################
            # Set result columns
            #####################

            if ($ResultColumns)
            {
                $CaView.SetResultColumnCount($ResultColumns.Count)

                foreach ($Property in $ResultColumns)
                {
                    $CaView.SetResultColumn($CaView.GetColumnIndex(0, $Property))
                }

            }

            #############
            # Get schema
            #############

            if ($GetSchema.IsPresent)
            {
                $Columns = $CaView.EnumCertViewColumn(0)

                while ($Columns.Next() -ge 0)
                {
                    Write-Output -InputObject (New-Object PSObject -Property ([Ordered]@{
                        Name = $Columns.GetName()
                        DisplayName = $Columns.GetDisplayName()
                        Type = [PROPTYPE]$Columns.GetType()
                        MaxLength = $Columns.GetMaxLength()
                    }))
                }
            }

            ###########
            # Get rows
            ###########

            else
            {
                $Row = $CaView.OpenView()

                while ($Row.Next() -ge 0)
                {
                    $Output = New-Object psobject
                    $Column = $Row.EnumCertViewColumn()

                    while ($Column.Next() -ge 0)
                    {
                        $CName = $Column.GetName() -replace '.*?\.', ''
                        $CValue = $Column.GetValue(1)

                        # Change values
                        switch ($CName)
                        {
                            'CertificateHash'
                            {
                                $CValue = $CValue -replace ' ', ''
                            }
                        }

                        # Add
                        switch ($CName)
                        {
                            # Skip
                            {
                                @(
                                    'ExtensionRawValue',
                                    'OtherProperty'
                                ) -contains $_
                            }
                            {
                                continue
                            }

                            default
                            {
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name $CName `
                                           -Value $CValue `
                                           -Force
                            }
                        }

                        # Add extra
                        switch ($CName)
                        {
                            'CertificateTemplate'
                            {
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'CertificateTemplateFriendlyName' `
                                           -Value ([Security.Cryptography.Oid]$CValue).FriendlyName `
                                           -Force
                            }


                            'ExtensionName'
                            {
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'ExtensionReadableName' `
                                           -Value (($Extensions.Keys | Where-Object { $Extensions[$_] -eq $CValue }) -replace "'", '') `
                                           -Force
                            }

                            'ExtensionRawValue'
                            {
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'ExtensionValue' `
                                           -Value (
                                                New-Object System.Security.Cryptography.AsnEncodedData(
                                                    $Output.ExtensionName,
                                                    [System.Convert]::FromBase64String($CValue)
                                                )
                                            ).Format($false) `
                                           -Force
                            }
                        }
                    }

                    Write-Output -InputObject $Output
                }
            }
        }
    }

    End
    {
        Remove-Variable Column, Row, CaView -ErrorAction SilentlyContinue
    }
}

# SIG # Begin signature block
# MIIY9AYJKoZIhvcNAQcCoIIY5TCCGOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUlDcH1Cg/BTSPsY2YVQjlT2nE
# LfmgghJ3MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUq+j9
# nc02rQxFo6+CGcPXZHlSq1swDQYJKoZIhvcNAQEBBQAEggIAnmR+xW+IjiRDqpno
# Vs1en+8yWL68dxUyaKwshBYWp9DioMbp2AaafiIImwhv8xXdhQxLtwroQjqyl7S8
# 3lPNd7eyRtZrmykCiKPdRz/2c92TRsdXv/j1Izrix9pdViyRZMil9aLYPYTZa966
# CGyLYVUBOqLYZSHF1fQBWF5ncav1L0942yABcezjk+YsENwSNA06NvHLDoh5J58t
# wXawUrxM/tNoycEpdnKLuaBj2+K/+SToxuZSADHKKNDvXzH88JCMKb4NgSYFGJFO
# McqL1wAIcOJcJWEGG6mBUYfLpcp7p2zXeqClSYQU3w1IjC5HY1ejllmKeoMtsjHw
# PeXLX6Gzz/S1WMC5jx3rwu27rcpGOCUElyEZ6WLxkL5lWrVnzB2sshWLTXwGX8SU
# k+yOHTOEsb9Qytf8OjJmgL96IaspKPjglOdGsLrAKFigv/iZU6+MhA91TKH1Oieg
# gRCEvWvzWFS2hU20KZ6Tfs7Lh5HwTpIPssQCmjyfh/5d2Cj+yqM0UDs6mm69tSI9
# t/cUuQ8MDDYfWYhEE6Vnj0fyrLSaI0t4fwkirALSsWc37Q1j7TuRMt/xpMhiXc3n
# r2IMY4LqeDn21bTwH+hk2x6Igdvn6/zLr83zc+d6whJOc8hLQxZzsBc47Ek7UtQ7
# kTXrZEsYjKtzk+/m/7RIcyFR516hggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNDI3MTQw
# MDA0WjAvBgkqhkiG9w0BCQQxIgQgg1ZvC/e+6TuYMqXwxCb9BvKwLHdBrSMrGtWC
# 85ipQ4MwDQYJKoZIhvcNAQEBBQAEggIAnRX0yfPC7p4LE7jiYmK9W5Zm/QZY60jl
# utrvPpOmYOzTX6KiCFeakx0KRIBZFu2948jo5+VE5yWqN7zRJg6veneTbZiD1hBl
# 2HZzCxiSJG23Y2hBMUW1Grvt/1FVTkwm+rE2cujjkyeYWJDtBoyKzBUs9BbSsMmG
# phaJMNgn44hOOX5ZaTirEA8lTlpld83aJd/dPBPU7BnFdeHkThE2wbuTmR5JZN4k
# 2vFsSfIab7nwC5HOJm/sc76XuZw+W7FuRDmDpNm3XInb4d5AdOmWh/pMcXb4WjD/
# 1rmZzQ9aYCXx1IhHBSSEjL5ziBrGIRj84UCPCf88jOnNNq5B/wS0QW2EGNKN7AgU
# KiDGjCe3LHtNJ0c2/JPSIhkW10nUZtc9BP9YYOiYIj1cA583lUAtA+OKbaz9EmzB
# 7JwEkQTXi3NGklmCobak1B+T1/U8BxVywLOBEXMX/dCKA4bWNmD6F3wuXW9HcRf+
# +BjpJ/YQ65Ho/m4lSoyDNVU3yPmD2dhstspnsP6XLijRULQ0/okprpR/uG1dR8x9
# b5Me0B+Qu++dgvRrzZNiEUrtKJin88bh604xtFXFxgmsEyYvOwjl6pTY93+Qx5w3
# WY9lwCyZdQbQegdJvKJWru0fROTYaPuyjIGeDfEC4Fi0gqwMkVWdbX1X305ptiQK
# JTOGV0dSeH4=
# SIG # End signature block
