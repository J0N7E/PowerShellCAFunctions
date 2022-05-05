<#
 .SYNOPSIS
    Get Certificate Authority View

 .DESCRIPTION
    Connect to CA and show database content from different tables

 .EXAMPLE
    Get all requests
    Get-CAView -Requests

    Get pending requests
    Get-CAView -Requests -Status Pending

    Get request with specific RequestId
    Get-CAView -Requests -RequestId <ID>

    Get request with specific Template OID
    Get-CAView -Requests -Template <OID>

    Get all extensions for specific RequestId
    Get-CAView -Extensions -RequestId <ID>

    Get specific extension for specific RequestId
    Get-CAView -Extensions -Name <extension> -RequestId <ID>

    Get number of requests
    Get-CAView -Requests -GetCount

    Get number of pending request of a certain template
    Get-CAView -Requests -GetCount -Status Pending -Template <OID>

    Get requests table schema
    Get-CAView -Requests -GetSchema

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

function Get-CAView
{
    [cmdletbinding(DefaultParameterSetName='Requests')]

    Param
    (
        [Parameter(ParameterSetName='Requests', Mandatory=$true)]
        [Parameter(ParameterSetName='Requests_GetCount', Mandatory=$true)]
        [Parameter(ParameterSetName='Requests_GetSchema', Mandatory=$true)]
        [Switch]$Requests,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [ValidateSet('Issued', 'Pending', 'Failed', 'Revoked')]
        [String]$Status,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [String]$Template,

        [Parameter(ParameterSetName='Extensions', Mandatory=$true)]
        [Parameter(ParameterSetName='Extensions_GetSchema', Mandatory=$true)]
        [Switch]$Extensions,

        [Parameter(ParameterSetName='Extensions')]
        [ArgumentCompleter({

            $ExtensionTable =
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
                $ExtensionTable
            }
            else
            {
                $ExtensionTable.Keys
            }
        })]
        [String]$Name,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Extensions')]
        [String]$RequestId,

        [Parameter(ParameterSetName='Attributes', Mandatory=$true)]
        [Parameter(ParameterSetName='Attributes_GetSchema', Mandatory=$true)]
        [Switch]$Attributes,

        [Parameter(ParameterSetName='Crl', Mandatory=$true)]
        [Parameter(ParameterSetName='Crl_GetSchema', Mandatory=$true)]
        [Switch]$Crl,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Extensions')]
        [Parameter(ParameterSetName='Attributes')]
        [Parameter(ParameterSetName='Crl')]
        [Array]$Properties,

        [Parameter(ParameterSetName='Requests_GetCount')]
        [Switch]$GetCount,

        [Parameter(ParameterSetName='Requests_GetSchema', Mandatory=$true)]
        [Parameter(ParameterSetName='Extensions_GetSchema', Mandatory=$true)]
        [Parameter(ParameterSetName='Attributes_GetSchema', Mandatory=$true)]
        [Parameter(ParameterSetName='Crl_GetSchema', Mandatory=$true)]
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

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/8116912a-59e6-4849-83dd-77b39b6370e0
        enum PROPTYPE
        {
            LONG     = 0x1
            DATETIME = 0x2
            BINARY   = 0x3
            STRING   = 0x4
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview2-settable
        enum CVRC_TABLE
        {
            REQUESTS   = 0x0
            EXTENSIONS = 0x3000
            ATTRIBUTES = 0x4000
            CRL        = 0x5000
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview-setrestriction
        enum CVR_SEEK
        {
            EQ = 0x1
            LE = 0x2
            LT = 0x4
            GE = 0x8
            GT = 0x10
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview-setrestriction
        enum CV_COLUMN
        {
            QUEUE         = -1 # Pending
            LOG_DEFAULT   = -2 # Issued, failed & revoked
            LOG_FAILED    = -3
            LOG_REVOKED   = -7
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
        # Functions
        ############

        Function Get-AllColumns
        {
            $Result = @()
            $Columns = $CaView.EnumCertViewColumn(0)

            while ($Columns.Next() -ge 0)
            {
                $Result += (New-Object PSObject -Property ([Ordered]@{
                    Name = $Columns.GetName()
                    DisplayName = $Columns.GetDisplayName()
                    Type = [PROPTYPE]$Columns.GetType()
                    MaxLength = $Columns.GetMaxLength()
                }))
            }

            Write-Output -InputObject $Result
        }

        ############
        # Set table
        ############

        if ($Requests.IsPresent)
        {
            $Table = 'Requests'
        }
        elseif ($Extensions.IsPresent)
        {
            $Table = 'Extensions'
        }
        elseif ($Attributes.IsPresent)
        {
            $Table = 'Attributes'
        }
        elseif ($Crl.IsPresent)
        {
            $Table = 'Crl'
        }

        #############
        # Extensions
        #############

        # Get extensions from argumentcompleter scriptblock
        $ExtensionTable = Invoke-Command -ScriptBlock $MyInvocation.MyCommand.Parameters.Item("Name").Attributes.ScriptBlock `
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
                'Requests'
                {
                    $CaView.SetTable([CVRC_TABLE]::REQUESTS)

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

                'Extensions'
                {
                    $CaView.SetTable([CVRC_TABLE]::EXTENSIONS)

                    if ($RequestId)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"ExtensionRequestId"),
                            [CVR_SEEK]::EQ,
                            0,
                            [int]$RequestId
                        )
                    }

                    if ($Name)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"ExtensionName"),
                            [CVR_SEEK]::EQ,
                            0,
                            $ExtensionTable["'$Name'"]
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

                'Attributes'
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

            #############
            # Get schema
            #############

            if ($GetSchema.IsPresent)
            {
                Write-Output -InputObject (Get-AllColumns)
            }

            ############
            # Get count
            ############

            elseif ($GetCount.IsPresent)
            {
                $CaView.SetResultColumnCount(0)

                $Row = $CaView.OpenView()
                $Row.Next() > $null

                Write-Output -InputObject $Row.GetMaxIndex()
            }

            #############
            # Get result
            #############

            else
            {
                #################
                # Get properties
                #################

                if ($Properties -notlike $null)
                {
                    if ('*' -in $Properties)
                    {
                        $ResultColumns = Get-AllColumns | Select-Object -ExpandProperty Name
                    }
                    else
                    {
                        $ResultColumns = $Properties
                    }
                }

                #####################
                # Set result columns
                #####################

                $CaView.SetResultColumnCount($ResultColumns.Count)

                foreach ($Property in $ResultColumns)
                {
                    $CaView.SetResultColumn($CaView.GetColumnIndex(0, $Property))
                }

                ###########
                # Get rows
                ###########

                $Row = $CaView.OpenView()

                while ($Row.Next() -ge 0)
                {
                    #Write-Host "Max: " $Row.GetMaxIndex()
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
                                           -Name 'ExtensionDisplayName' `
                                           -Value (($ExtensionTable.Keys | Where-Object { $ExtensionTable[$_] -eq $CValue }) -replace "'", '') `
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
# MIIZBgYJKoZIhvcNAQcCoIIY9zCCGPMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpQcFduCJwHlxpWWsxKha6+RF
# gWKgghKHMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMTA2MDcxMjUwMzZaFw0yMzA2MDcx
# MzAwMzNaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzdFz3tD9N0VebymwxbB7s+YMLFKK9LlPcOyyFbAoRnYKVuF7Q6Zi
# fFMWIopnRRq/YtahEtmakyLP1AmOtesOSL0NRE5DQNFyyk6D02/HFhpM0Hbg9qKp
# v/e3DD36uqv6DmwVyk0Ui9TCYZQbMDhha/SvT+IS4PBDwd3RTG6VH70jG/7lawAh
# mAE7/gj3Bd5pi7jMnaPaRHskogbAH/vRGzW+oueG3XV9E5PWWeRqg1bTXoIhBG1R
# oSWCXEpcHekFVSnatE1FGwoZHTDYcqNnUOQFx1GugZE7pmrZsdLvo/1gUCSdMFvT
# oU+UeurZI9SlfhPd6a1jYT/BcgsZdghWUO2M8SCuQ/S/NuotAZ3kZI/3y3T5JQnN
# 9l9wMUaoIoEMxNK6BmsSFgEkiQeQeU6I0YT5qhDukAZDoEEEHKl17x0Q6vxmiFr0
# 451UPxWZ19nPLccS3i3/kEQjVXc89j2vXnIW1r5UHGUB4NUdktaQ25hxc6c+/Tsx
# 968S+McqxF9RmRMp4g0kAFhBHKj7WhUVt2Z/bULSyb72OF4BC54CCSt1Q4eElh0C
# 1AudkZgj9CQKFIyveTBFsi+i2g6D5cIpl5fyQQnqDh/j+hN5QuI8D7poLe3MPNA5
# r5W1c60B8ngrDsJd7XnJrX6GdJd2wIPh1RmzDlmoUxVXrgnFtgzeTUUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFEPCLoNYgwyQVHRrBSI9l0nSMwnLMA0G
# CSqGSIb3DQEBCwUAA4ICAQBiMW8cSS4L1OVu4cRiaPriaqQdUukgkcT8iWGWrAHL
# TFPzivIPI5+7qKwzIJbagOM3fJjG0e6tghaSCPfVU+sPWvXIKF3ro5XLUfJut6j5
# qUqoQt/zNuWpI12D1gs1NROWnJgqe1ddmvoAOn5pZyFqooC4SnD1fT7Srs+G8Hs7
# Qd2j/1XYAphZfLXoiOFs7uzkQLJbhmikhEJQKzKE4i8dcsoucNhe2lvNDftJqaGl
# oALzu04y1LcpgCDRbvjU0YDStZwKSEj9jvz89xpl5tMrgGWIK8ghjRzGf0iPhqb/
# xFOFcKP2k43X/wXWa9W7PlO+NhIlZmTM/W+wlgrRfgkawy2WLpO8Vop+tvVwLdyp
# 5n4UxRDXBhYd78Jfscb0fwpsU+DzONLrJEwXjdj3W+vdEZs7YIwAnsCGf8NznXWp
# N9D7OzqV0PT2Szkao5hEp3nS6dOedw/0uKAz+l5s7WJOTLtFjDhUk62g5vIZvVK2
# E9TWAuViPmUkVugnu4kV4c870i5YgRZz9l4ih5vL9XMoc4/6gohLtUgT4FD0xKXn
# bwtl/LczkzDO9vKLbx93ICmNJuzLj+K8S4AAo8q6PTgLZyGlozmTWRa3SmGVqTNE
# suZR41hGNpjtNtIIiwdZ4QuP8cj64TikUIoGVNbCZgcPDHrrz84ZjAFlm7H9SfTK
# 8jCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbGMIIErqADAgEC
# AhAKekqInsmZQpAGYzhNhpedMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwMzI5
# MDAwMDAwWhcNMzMwMzE0MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIy
# IC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALkqliOmXLxf1knw
# FYIY9DPuzFxs4+AlLtIx5DxArvurxON4XX5cNur1JY1Do4HrOGP5PIhp3jzSMFEN
# MQe6Rm7po0tI6IlBfw2y1vmE8Zg+C78KhBJxbKFiJgHTzsNs/aw7ftwqHKm9MMYW
# 2Nq867Lxg9GfzQnFuUFqRUIjQVr4YNNlLD5+Xr2Wp/D8sfT0KM9CeR87x5MHaGjl
# RDRSXw9Q3tRZLER0wDJHGVvimC6P0Mo//8ZnzzyTlU6E6XYYmJkRFMUrDKAz200k
# heiClOEvA+5/hQLJhuHVGBS3BEXz4Di9or16cZjsFef9LuzSmwCKrB2NO4Bo/tBZ
# mCbO4O2ufyguwp7gC0vICNEyu4P6IzzZ/9KMu/dDI9/nw1oFYn5wLOUrsj1j6siu
# gSBrQ4nIfl+wGt0ZvZ90QQqvuY4J03ShL7BUdsGQT5TshmH/2xEvkgMwzjC3iw9d
# RLNDHSNQzZHXL537/M2xwafEDsTvQD4ZOgLUMalpoEn5deGb6GjkagyP6+SxIXuG
# Z1h+fx/oK+QUshbWgaHK2jCQa+5vdcCwNiayCDv/vb5/bBMY38ZtpHlJrYt/YYcF
# aPfUcONCleieu5tLsuK2QT3nr6caKMmtYbCgQRgZTu1Hm2GV7T4LYVrqPnqYklHN
# P8lE54CLKUJy93my3YTqJ+7+fXprAgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHQYDVR0OBBYEFI1kt4kh/lZYRIRhp+pvHDaP3a8NMFoGA1Ud
# HwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUF
# BwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# WAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAA0tI3Sm0fX46kuZPwHk9gzkrxad2bOMl4IpnENvAS2rOLVw
# Eb+EGYs/XeWGT76TOt4qOVo5TtiEWaW8G5iq6Gzv0UhpGThbz4k5HXBw2U7fIyJs
# 1d/2WcuhwupMdsqh3KErlribVakaa33R9QIJT4LWpXOIxJiA3+5JlbezzMWn7g7h
# 7x44ip/vEckxSli23zh8y/pc9+RTv24KfH7X3pjVKWWJD6KcwGX0ASJlx+pedKZb
# NZJQfPQXpodkTz5GiRZjIGvL8nvQNeNKcEiptucdYL0EIhUlcAZyqUQ7aUcR0+7p
# x6A+TxC5MDbk86ppCaiLfmSiZZQR+24y8fW7OK3NwJMR1TJ4Sks3KkzzXNy2hcC7
# cDBVeNaY/lRtf3GpSBp43UZ3Lht6wDOK+EoojBKoc88t+dMj8p4Z4A2UKKDr2xpR
# oJWCjihrpM6ddt6pc6pIallDrl/q+A8GQp3fBmiW/iqgdFtjZt5rLLh4qk1wbfAs
# 8QcVfjW05rUMopml1xVrNQ6F1uAszOAMJLh8UgsemXzvyMjFjFhpr6s94c/MfRWu
# FL+Kcd/Kl7HYR+ocheBFThIcFClYzG/Tf8u+wQ5KbyCcrtlzMlkI5y2SoRoR/jKY
# pl0rl+CL05zMbbUNrkdjOEcXW28T2moQbh9Jt0RbtAgKh1pZBHYRoad3AhMcMYIF
# 6TCCBeUCAQEwJDAQMQ4wDAYDVQQDDAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUXhkbInHZxuA1H9cxewMSttLW3KkwDQYJKoZIhvcNAQEB
# BQAEggIAdtgAn4sMilbyfSrgYueBexE7cMjcMVXiYkKWCjXDWvnyEAxLTnlo5SUs
# qZE8uvLpweYJ0Mv9dOjXotWi8LVAHLfe+4v0WJEe7bwxPg2oMYlXK48mR2+tSlt8
# vsJ4CukOP3vujHMXdV75CBogthZTiljulpoUr0HGy6XCLHgG0Wq1Z1Ab3pQYN0yr
# sCCvyICryNLLIGRpqSFMwkBQsilBlL/kT794uJe8J97eoks1QjAoGFKbIMU7tdjs
# ULS0k/surgGW+27U8lesmq7zEIVHVLSR0BLUuefrCanzjJ9uc566er3e2uSaGDsB
# 0XiGzDyt9TKUFYC3GeAgrG5+KwC5gUXgc30iNY7PgV6nznZIbq1ChSCSrzl8eQ4M
# /CSj+vU8q3KdAkEDQ2NboPS+NmgO3G1RtppfmrnExlLv3PlfYD89ogSl9x8yvGl9
# /skkdQ5zep4M2LeblkBhigcf4pPf5MRDGmf0uOlD2BRYfoNBBiHaK5naj/oeLrc4
# V2rdL3b43SJ1B/ymDUKC28jNK9hVXslLeosMAwNVsf+lmHOHm4zDwZJgG4esQiED
# U1HxrAyfHpYji6E1E7w0sidwrA51DrxKceBPmDWGit5+0lwDYzkT/1NGAaGqwmgO
# tS53e+hOyNuSpORlN7FZr+VnPhprWqKMIEWyrirY0gFvazHAE3uhggMgMIIDHAYJ
# KoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjIwNTA1MTEwMDAyWjAvBgkqhkiG9w0BCQQxIgQgjLTIEoMIEbEW
# xmV5EhyzOV1xPTsSxy2hfMJ70sO1bfkwDQYJKoZIhvcNAQEBBQAEggIAOOrpClad
# HiSZ5qJgpBZGs1rYhp+OQYeFtkQa5cyZPmYQw6xKsms+lYhDy/5kupR1BLGZVXWr
# QRWLIhrwuPHJD42Up8GPd7klSX7+eeMEFKg817thUCQ37pU4dspbR16oQlUc9jPS
# vHY3hp20pvXhMtCPcPfecI5Aqt1M7YAW0EkF+tCKlLuB822P1h3JwKDt0fJn/GkX
# hsIxsfvHuBWjn3ekyaAbUFtaJ2pXVyQtSJLhKb2iemTjL3SB0YRyo4OvuJJ49ppZ
# cIQKKkxa9bPQ0Nu+tDdtOyVMTwZqvCs4TUQJrBfsXsbSV+ImdrSsHRPF8V1ydxD3
# 6PoeZOqJ560p6odzUdu2gwBzYWevF2OC7CHKdzPC6vugO89SfTe1He0ssQ21p6my
# FkvAzTrbrTDiXjaU5iqdB7hhyKtCc2ZgJKFkmKiwVhvkOgD5i19ZQ5qR4+nHIfpR
# 4qYTSlI6kfI2YerzCSigv7NTdzXhTjiSaifBv7CJ6a5CypiKYBIhqI1aLtACcXZd
# QTdcNAJKfxIbFZvvULxDDlp4l3n7tTphRYwtKQkezG7Rq+J9aEWIXtn4V2hkdUYl
# m4hthkIk/H4H2AVQHrvKrKMQonq+O6ZS00bi/vHrfxz07ixlS6WKaRlcvsv8Ru9B
# T7UZRxGCOWR+OsHfVD5E5Mau4WP5chvEWPE=
# SIG # End signature block
