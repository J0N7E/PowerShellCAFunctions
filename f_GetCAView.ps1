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

    Get last requestId
    Get-CAView -Requests -GetMaxId

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
        [Parameter(ParameterSetName='Requests_GetMaxId', Mandatory=$true)]
        [Parameter(ParameterSetName='Requests_GetSchema', Mandatory=$true)]
        [Switch]$Requests,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [ValidateSet('Issued', 'Pending', 'Failed', 'Revoked')]
        [String]$Status,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [String]$Template,

        [Parameter(ParameterSetName='Extensions', Mandatory=$true)]
        [Parameter(ParameterSetName='Extensions_GetSchema', Mandatory=$true)]
        [Switch]$Extensions,

        [Parameter(ParameterSetName='Extensions')]
        [ArgumentCompleter({

            $ExtensionTable = @{}
            @(
                '1.2.840.113549.1.9.15'
                '1.3.6.1.4.1.311.20.2'
                '1.3.6.1.4.1.311.21.1'
                '1.3.6.1.4.1.311.21.7'
                '1.3.6.1.4.1.311.21.10'
                '1.3.6.1.5.5.7.1.1'
                '1.3.6.1.5.5.7.48.1.5'
                '2.5.29.14'
                '2.5.29.15'
                '2.5.29.17'
                '2.5.29.19'
                '2.5.29.31'
                '2.5.29.32'
                '2.5.29.35'
                '2.5.29.37'
            ) | ForEach-Object {
                $ExtensionTable += @{
                    "'$([System.Security.Cryptography.Oid]::New($_).FriendlyName)'" = $_
                }
            }

            if ($args[4].GetHashTable)
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

        [Parameter(ParameterSetName='Requests')]
        [String]$SerialNumber,

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

        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [Switch]$GetMaxId,

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
        enum CERT_CONFIG
        {
            DEFAULT           = 0
            UIPICK            = 0x1
            FIRST             = 0x2
            LOCAL             = 0x3
            LOCALACTIVE       = 0x4
            UIPICKSKIPLOCALCA = 0x5
        }

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/8116912a-59e6-4849-83dd-77b39b6370e0
        enum PROPTYPE
        {
            LONG     = 0
            DATETIME = 0x2
            BINARY   = 0x3
            STRING   = 0x4
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview2-settable
        enum CVRC_TABLE
        {
            REQUESTS   = 0
            EXTENSIONS = 0x3000
            ATTRIBUTES = 0x4000
            CRL        = 0x5000
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview-setrestriction
        enum CVR_SEEK
        {
            EQ = 0
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

        # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/CertSrv.h
        enum DB_DISP
        {
            ACTIVE        = 8
            PENDING       = 9
            FOREIGN       = 12 # Archived
            CA_CERT       = 15
            CA_CERT_CHAIN = 16
            KRA_CERT      = 17
            ISSUED        = 20
            REVOKED       = 21
            ERROR         = 30
            DENIED        = 31
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
            $Config = $CA.GetConfig([CERT_CONFIG]::LOCAL)

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
                                [DB_DISP]::ISSUED
                            )

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'NotBefore',
                                'NotAfter',
                                'DistinguishedName',
                                'SerialNumber',
                                'CertificateHash',
                                'CertificateTemplate'
                            )
                        }

                        'Pending'
                        {
                            $CaView.SetRestriction([CV_COLUMN]::QUEUE, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.CommonName',
                                'Request.SubmittedWhen',
                                'DistinguishedName',
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
                                'Request.SubmittedWhen',
                                'Request.StatusCode',
                                'Request.DispositionMessage',
                                'DistinguishedName',
                                'CertificateTemplate'
                            )
                        }

                        'Revoked'
                        {
                            $CaView.SetRestriction(
                                $CaView.GetColumnIndex(0, 'Disposition'),
                                [CVR_SEEK]::EQ,
                                0,
                                [DB_DISP]::REVOKED
                            )

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RevokedWhen',
                                'Request.RevokedReason',
                                'DistinguishedName',
                                'SerialNumber',
                                'CertificateHash',
                                'CertificateTemplate'
                            )
                        }

                        default
                        {
                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'DistinguishedName'
                            )
                        }
                    }

                    if ($RequestId)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"Request.RequestID"),
                            [CVR_SEEK]::EQ,
                            0,
                            [Int]$RequestId
                        )
                    }

                    if ($SerialNumber)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"SerialNumber"),
                            [CVR_SEEK]::EQ,
                            0,
                            $SerialNumber
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
            # Get Id
            # Get count
            ############

            elseif ($GetMaxId.IsPresent -or
                    $GetCount.IsPresent)
            {
                $CaView.SetResultColumnCount(1)
                $CaView.SetResultColumn($CaView.GetColumnIndex(0, 'Request.RequestID'))

                $Row = $CaView.OpenView()

                $Next = $Row.Next()
                $Max  = $Row.GetMaxIndex()

                if ($GetCount.IsPresent)
                {
                    Write-Output -InputObject $Max
                }
                else
                {
                    if ($Next -ge 0)
                    {
                        while ($Next -lt $Max)
                        {
                            $Next = $Row.Next()
                        }

                        $Column = $Row.EnumCertViewColumn()
                        $Column.Next() > $null

                        Write-Output -InputObject $Column.GetValue(1)
                    }
                }
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
                    $Output = New-Object psobject
                    $Column = $Row.EnumCertViewColumn()

                    while ($Column.Next() -ge 0)
                    {
                        $CName = $Column.GetName() -replace '.*?\.', ''
                        $CValue = $Column.GetValue(1)

                        # Change values
                        switch ($CName)
                        {
                            { $_ -in @('CertificateHash',
                                       'SubjectKeyIdentifier') }
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
                            'Disposition'
                            {
                                # DispositionEnum
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'DispositionEnum' `
                                           -Value ([string][DB_DISP]$CVAlue) `
                                           -Force
                            }

                            'CertificateTemplate'
                            {
                                # CertificateTemplateFriendlyName
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'CertificateTemplateFriendlyName' `
                                           -Value ([Security.Cryptography.Oid]$CValue).FriendlyName `
                                           -Force
                            }


                            'ExtensionName'
                            {
                                # ExtensionDisplayName
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'ExtensionDisplayName' `
                                           -Value (($ExtensionTable.Keys | Where-Object { $ExtensionTable[$_] -eq $CValue }) -replace "'", '') `
                                           -Force
                            }

                            'ExtensionRawValue'
                            {
                                # ExtensionValue
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
# MIIeuwYJKoZIhvcNAQcCoIIerDCCHqgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYH5sOqnqe1F9dK+/uktSAzB0
# fbagghg8MIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# 8jCCBbEwggSZoAMCAQICEAEkCvseOAuKFvFLcZ3008AwDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDYwOTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5
# BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQwF
# AAOCAQEAmhYCpQHvgfsNtFiyeK2oIxnZczfaYJ5R18v4L0C5ox98QE4zPpA854kB
# dYXoYnsdVuBxut5exje8eVxiAE34SXpRTQYy88XSAConIOqJLhU54Cw++HV8LIJB
# YTUPI9DtNZXSiJUpQ8vgplgQfFOOn0XJIDcUwO0Zun53OdJUlsemEd80M/Z1UkJL
# HJ2NltWVbEcSFCRfJkH6Gka93rDlkUcDrBgIy8vbZol/K5xlv743Tr4t851Kw8zM
# R17IlZWt0cu7KgYg+T9y6jbrRXKSeil7FAM8+03WSHF6EBGKCHTNbBsEXNKKlQN2
# UVBT1i73SkbDrhAscUywh7YnN0RgRDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9
# KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMy
# MjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRp
# bWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaG
# NQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp9
# 85yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+r
# GSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpX
# evA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs
# 5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymW
# Jy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmC
# KseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaz
# nTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2
# SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YS
# UZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkB
# KAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNV
# HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAf
# BgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMG
# A1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBN
# E88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822
# EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2
# qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2
# ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6ad
# cq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TN
# OXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOr
# pgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUs
# HicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJig
# K+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2
# AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4
# GqEr9u3WfPwwggbGMIIErqADAgECAhAKekqInsmZQpAGYzhNhpedMA0GCSqGSIb3
# DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0EwHhcNMjIwMzI5MDAwMDAwWhcNMzMwMzE0MjM1OTU5WjBMMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG0Rp
# Z2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALkqliOmXLxf1knwFYIY9DPuzFxs4+AlLtIx5DxArvurxON4XX5c
# Nur1JY1Do4HrOGP5PIhp3jzSMFENMQe6Rm7po0tI6IlBfw2y1vmE8Zg+C78KhBJx
# bKFiJgHTzsNs/aw7ftwqHKm9MMYW2Nq867Lxg9GfzQnFuUFqRUIjQVr4YNNlLD5+
# Xr2Wp/D8sfT0KM9CeR87x5MHaGjlRDRSXw9Q3tRZLER0wDJHGVvimC6P0Mo//8Zn
# zzyTlU6E6XYYmJkRFMUrDKAz200kheiClOEvA+5/hQLJhuHVGBS3BEXz4Di9or16
# cZjsFef9LuzSmwCKrB2NO4Bo/tBZmCbO4O2ufyguwp7gC0vICNEyu4P6IzzZ/9KM
# u/dDI9/nw1oFYn5wLOUrsj1j6siugSBrQ4nIfl+wGt0ZvZ90QQqvuY4J03ShL7BU
# dsGQT5TshmH/2xEvkgMwzjC3iw9dRLNDHSNQzZHXL537/M2xwafEDsTvQD4ZOgLU
# MalpoEn5deGb6GjkagyP6+SxIXuGZ1h+fx/oK+QUshbWgaHK2jCQa+5vdcCwNiay
# CDv/vb5/bBMY38ZtpHlJrYt/YYcFaPfUcONCleieu5tLsuK2QT3nr6caKMmtYbCg
# QRgZTu1Hm2GV7T4LYVrqPnqYklHNP8lE54CLKUJy93my3YTqJ+7+fXprAgMBAAGj
# ggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# HwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFI1kt4kh
# /lZYRIRhp+pvHDaP3a8NMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3Rh
# bXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1l
# U3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAA0tI3Sm0fX46kuZPwHk
# 9gzkrxad2bOMl4IpnENvAS2rOLVwEb+EGYs/XeWGT76TOt4qOVo5TtiEWaW8G5iq
# 6Gzv0UhpGThbz4k5HXBw2U7fIyJs1d/2WcuhwupMdsqh3KErlribVakaa33R9QIJ
# T4LWpXOIxJiA3+5JlbezzMWn7g7h7x44ip/vEckxSli23zh8y/pc9+RTv24KfH7X
# 3pjVKWWJD6KcwGX0ASJlx+pedKZbNZJQfPQXpodkTz5GiRZjIGvL8nvQNeNKcEip
# tucdYL0EIhUlcAZyqUQ7aUcR0+7px6A+TxC5MDbk86ppCaiLfmSiZZQR+24y8fW7
# OK3NwJMR1TJ4Sks3KkzzXNy2hcC7cDBVeNaY/lRtf3GpSBp43UZ3Lht6wDOK+Eoo
# jBKoc88t+dMj8p4Z4A2UKKDr2xpRoJWCjihrpM6ddt6pc6pIallDrl/q+A8GQp3f
# BmiW/iqgdFtjZt5rLLh4qk1wbfAs8QcVfjW05rUMopml1xVrNQ6F1uAszOAMJLh8
# UgsemXzvyMjFjFhpr6s94c/MfRWuFL+Kcd/Kl7HYR+ocheBFThIcFClYzG/Tf8u+
# wQ5KbyCcrtlzMlkI5y2SoRoR/jKYpl0rl+CL05zMbbUNrkdjOEcXW28T2moQbh9J
# t0RbtAgKh1pZBHYRoad3AhMcMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQDDAVKME43
# RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUO4jHR5QPbUBtq8RP
# K3z94B179E0wDQYJKoZIhvcNAQEBBQAEggIAKEt9qwq0h1oG2zt0ROQoUadWSN6F
# DJjDOWW/o3lRV4jy68P29Bp5UDCz4yAy6ifelVQ8DWcN46YAIibZW0OyPIA6awK7
# z0DFeXi7aRNZt/Nd8sFa+ev0PH9y+WoNJYCTsjQO+Op5cN2ZvdqhB/CQSDsVNnr9
# XRaAtTCeUrOjFEpyDxIdtZ86ejzPOuCpsE8IYUPEOoTva7mMUpgjRAgBmfkACL1Q
# 3Z0zdaD7FHR/x8N2U77Fz1NgvwQSHVwIoEB8ktyeb6M/JTmksNYcJjDZBgeEjVLy
# jIAn7DFH0S/lcIbCO6BngUkoQLyhHPpJwIxNeXML1IWanqU5fvWFVd217mTBFAw0
# i7+mhzk+/RhGWNInXnvrW4Q1pb1TCB5vgR+Kkr28tsjWPWi+MRS2eLq3TvCES2k9
# lx4NNlJgOXaFDTAAh8sq3Y8/GuzzeZZNtL+mgbK/04AfNApjP/VkNz1TvZkIdNjD
# Rv2IxoOa3OtBX6XnuRtYBPmVu0KhvVNK+9EWxrxcD5VagEJBfK8yTllslJpkfcdW
# /CLILCOn6mvQ430rmD629bimOERrkSPaA+6DEfKZDOrrd+0c6QlAFah5rxnhX3d1
# Vgl53Qi8S0bYbNqVtJUrgYllbdXvvN8qspVYdl7a+8p+FTCJPxrffsGj7SqmhsIr
# wjOPNBNPhC7/dTyhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRp
# Z2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENB
# AhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNjIyMDAwMDAxWjAvBgkq
# hkiG9w0BCQQxIgQgrWbgT+zD2tPCRRBC/IzJwripcJ5rL6Qi7EeJLZ5uRb4wDQYJ
# KoZIhvcNAQEBBQAEggIAVeO+0I6xnFUr3UA/D1vNH/xT98w4qNO5S+lMyEuWWYZD
# J63JfKETwEU5a4xOltI+QswV+qXQkGD1snrVByxk/9AZYNi3D2H3LrJLUxv4evnX
# KWqUUm8z3MpSEbTbbtcGQgEsHhSkJd56nSgS5IXr5P5+ZO0cqoADi06EhVgepWiS
# DvO+fTDXONl1t7o3xd6MHmdnUBSvncnKSmQo4+ue7M7CNxwDXsLv2oXQ2t7yqgHs
# VeddU8N6wXUde8FRTsRnWsSN3cJs0BZLkbgQdu0ePpf6ZvGTTsateMCK8mn08pGm
# kHzp4EUeGA9YmZKZMXDNNi5XeNQFc+vapqLl5dqtdMxM/NYB6//IQUxdW1a4G9DE
# kcToUpQa6gKRjoWnycp3udFXHQ1kUA31olAjjeqYGYsik0XSQEuZw5EcXWk91W+D
# rrLyellpBQx9RKoMr8XBd/l7Y7szgn3Xon66akDXF30K4DbJJibQEF69xLGdBZsx
# q3dUS7vtrBle1bD2uphVxsnz8V7iy/JxhhH5bzTi9WDWygOkFmXKouCwUfmrUAXy
# KYxep+iFsmxMB9dcI7vVg/sD410Y/hh1cNL1Ud63Q1wgvurbYse/W0LFPM6VLpOi
# jhEP0unxgeHtaS/8xj3fJOnxCayapJdmqsKSJGcnLua5xlglg5LYnIN0OK2pHnU=
# SIG # End signature block
