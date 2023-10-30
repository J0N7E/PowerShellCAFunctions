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
    CREDIT TO Vadims Podāns without him this would not have been possible

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
        [Parameter(ParameterSetName='Extensions')]
        [String]$RequestId,

        [Parameter(ParameterSetName='Requests')]
        [String]$SerialNumber,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [String]$Template,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [DateTime]$NotBefore,

        [Parameter(ParameterSetName='Requests')]
        [Parameter(ParameterSetName='Requests_GetCount')]
        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [DateTime]$NotAfter,

        [Parameter(ParameterSetName='Requests_GetCount')]
        [Switch]$GetCount,

        [Parameter(ParameterSetName='Requests_GetMaxId')]
        [Switch]$GetMaxId,

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
            QUEUE_DEFAULT = -1 # Not Resolved: Pending
            LOG_DEFAULT   = -2 # Resolved: Issued, failed & revoked
            LOG_FAILED    = -3 # Failed
            LOG_REVOKED   = -7 # Revoked
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

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/d2fb086e-8447-409b-bd5e-60c9e6b05c14
        enum REVOCATION_REASON
        {
            UNSPECIFIED             = 0
            KEY_COMPROMISE          = 1
            CA_COMPROMISE           = 2
            AFFILIATION_CHANGED     = 3
            SUPERSEDED              = 4
            CESSATION_OF_OPERATION  = 5
            CERTIFICATE_HOLD        = 6
            REMOVE_FROM_CRL         = 8
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
                                'CommonName',
                                'NotBefore',
                                'NotAfter'
                            )
                        }

                        'Pending'
                        {
                            $CaView.SetRestriction([CV_COLUMN]::QUEUE_DEFAULT, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'Request.CommonName',
                                'Request.SubmittedWhen'
                            )
                        }

                        'Failed'
                        {
                            $CaView.SetRestriction([CV_COLUMN]::LOG_FAILED, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'Request.StatusCode',
                                'Request.DispositionMessage',
                                'Request.CommonName',
                                'Request.SubmittedWhen'
                            )
                        }

                        'Revoked'
                        {
                            <#
                            $CaView.SetRestriction(
                                $CaView.GetColumnIndex(0, 'Disposition'),
                                [CVR_SEEK]::EQ,
                                0,
                                [DB_DISP]::REVOKED
                            )
                            #>
                            $CaView.SetRestriction([CV_COLUMN]::LOG_REVOKED, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RevokedReason',
                                'CommonName',
                                'Request.RevokedWhen'
                            )
                        }

                        default
                        {
                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.RequesterName',
                                'Request.Disposition',
                                'CommonName',
                                'NotBefore',
                                'NotAfter'
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

                    if ($NotBefore)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"NotBefore"),
                            [CVR_SEEK]::GE,
                            0,
                            $NotBefore
                        )
                    }

                    if ($NotAfter)
                    {
                        $CaView.SetRestriction(
                            $CaView.GetColumnIndex(0,"NotAfter"),
                            [CVR_SEEK]::LE,
                            0,
                            $NotAfter
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
                    if ($Properties -match '\*')
                    {
                        $ResultColumns = Get-AllColumns | Select-Object -ExpandProperty Name
                    }
                    elseif ($Properties -match '\+')
                    {
                        $ResultColumns += $Properties.Replace('+', '')
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
                                # Disposition enum
                                Add-Member -InputObject $Output `
                                           -MemberType NoteProperty `
                                           -Name 'DispositionEnum' `
                                           -Value ([string][DB_DISP]$CValue) `
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

                            'RevokedReason'
                            {
                                if ($CValue)
                                {
                                    # Revoked reason enum
                                    Add-Member -InputObject $Output `
                                               -MemberType NoteProperty `
                                               -Name 'RevokedReasonEnum' `
                                               -Value ([string][REVOCATION_REASON]$CValue) `
                                               -Force

                                }
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
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrxrTkIzsM23bWOM9edO9JkM1
# UWSgghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMzA5MDcxODU5NDVaFw0yODA5MDcx
# OTA5NDRaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0cNYCTtcJ6XUSG6laNYH7JzFfJMTiQafxQ1dV8cjdJ4ysJXAOs8r
# nYot9wKl2FlKI6eMT6F8wRpFbqKqmTpElxzM+fzknD933uEBLSAul/b0kLlr6PY2
# oodJC20VBAUxthFUYh7Fcni0dwz4EjXJGxieeDDLZYRT3IR6PzewaWhq1LXY3fhe
# fYQ1Q2nqHulVWD1WgucgIFEfUJCWcOvfmJBE+EvkNPVoKAqFxJ61Z54z8y6tIjdK
# 3Ujq4bgROQqLsFMK+mII1OqcLRKMgWkVIS9nHfFFy81VIMvfgaOpoSVLatboxAnO
# mn8dusJA2DMH6OL03SIBb/FwE7671sjtGuGRp+nlPnkvoVqFET9olZWDxlGOeeRd
# Tc3jlcEPb9XLpiGjlQfMfk4ycSwraJqn1cYDvSXh3K6lv0OeSLa/VQRlEpOmttKB
# EI/eFMK76DZpGxFvv1xOg1ph3+01hCboOXePu9qSNk5hnIrBEb9eqks3r5ZDfrlE
# wjFUhd9kLe2UKEaHK7HI9+3x1WhTgNRKWzKzqUcF9aVlpDQRplqbUMJEzMxzRUIk
# 01NDqw46gjUYet6VnIPqnQAe2bLWqDMeL3X6P7cAHxw05yONN51MqyBFdYC1MieY
# uU4MOoIfIN6M6vEGn7avjw9a4Xpfgchtty2eNgIRg+KuJ3Xxtd1RDjUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFFjQBHg94o+OtZeRxQoH0mKFzMApMA0G
# CSqGSIb3DQEBCwUAA4ICAQBSglLs0PCn7g36iGRvqXng/fq+6nL3ZSLeLUXSDoFX
# KhJ3K6wFSiHBJtBYtWc7OnHIbIg1FFFAi5GIP56MMwmN4NoY0DrBN0Glh4Jq/lhu
# iah5zs/9v/aUvtwvBD4NVX0G/wJuRuX697UQZrtkWninB46BMPU+gEg1ctn0V4zQ
# 3fazrcmJqD9xIwKlOXsvxOAO5OJ51ucdsubD6QkJa++4bGd5HhoC8/O18mxz6YYa
# gOnXWJObybkwdkDC9MUjy5wZNAv48DkUM+OArbfM3ZpfcAVTnDrfuzpoOKTkcdgb
# N+4VXJC/ly1D98f+IpEOw1UItX8Hg67WfU9sXcIY+fghzHPHF864vp2F/G75i02M
# oqeRpeO3guwum3DbKCkKts5S1QXnE7pmeqe4U595jCVhELeB6ifrvj0ulSlOU5GE
# twNY5VL0T3cHegBmtQXFfQoT6vboF6m9I7kVlKGT4WI8M/UQYCQ2ZP3HTjdSHt9U
# cJslGMqDxhbkGLH49ESP5ghbRddll24dsw0dF96lOIEmhB01UNIz40TonraK3cku
# Jdnrh/2fHYbycGHjkowiMUJQaihbZBRKvBHhrM7OuQ96M9g8Gk2RCIqdX0lO8n2y
# S8fnzEoWe8FVwE5bgA5Nwl6iYdoszubYgh+siVMe2EFaUh0DXXpbQ3JxjMGe5qVK
# 1zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
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
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEz
# MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# IDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6
# OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp
# 52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF
# 6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G4
# 5lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7p
# Be6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAs
# NJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU
# 6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwK
# WEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFx
# smxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbR
# yV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPL
# QHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4E
# FgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCp
# tZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX
# 4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoF
# eoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+nji
# kxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBB
# Jt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJ
# A+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcs
# QdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE
# 5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS
# 2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3
# CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUb
# c7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYoxggXpMIIF5QIBATAkMBAxDjAMBgNV
# BAMMBUowTjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQOG52A
# ydtrZH5k+DATZS68B+qH8DANBgkqhkiG9w0BAQEFAASCAgDMc+JQh04cezrYKKY8
# qBhpNvDyrmiSIYI709HaHbJw+kpjh+fbq9fG+msoD7s9ZJNwT2145C1HNABJWpu8
# FGrMeIABnnArVD6TV0BOOLJqduVH+YFWMxJVlHhLUmbENaIadg9gjx1yC9Hi2/bf
# jWecW2CnN0n8S/21FToD/KrPWuAw2oen8BDfXSUzRavVhWHCm7m8B+1DZmgiNhza
# SOc2Vf0JfBNnuYqJEUDv5IReL2cISIXAW5jRx2iZvR9w6PayBKJaTcYqVV3weaia
# KHECp5Ih+nG77eX43etQp0vTkLmh5Wv0x6Ulp63qX+0G2uYS3WfEEKQBQKrGxcTQ
# x8MS/asWdF9kPk7zBxEpMWiHdV2eIlP5czaPyr4uJwolgHu6CgQPuGrbF6clvq4M
# dKvcjSHDRvnoCwZkMOsbkIqg0Ud0dtepM2loaw/2zjN/MO4xcQzVswJ2aWdTI65k
# rp5UmTmnOfwOZQE3D5qMNeyfu9KO1rtDNZnUTVlM4cVbAc/CBb4FuiS6qRmgbKmO
# foAJZFdIRgvq7ALOwkc5Ni5GCAiwJBbf0b17XrxNgfb+aCsTjo7NXAq+7uHZ8FQM
# Zd3/bBUvwE//fsoiiec2gSMcaS0iGYcEiNcQAOsOUhRIkUeEI1NSCQVzUjizhLCt
# cbLVEcJKq7KL8PF7ROQPo52juaGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzEwMzAxNzAw
# MDBaMC8GCSqGSIb3DQEJBDEiBCAokstiFPN059dSZJAVKqQh8yFOdOWL5YbzVXzf
# rD5ycDANBgkqhkiG9w0BAQEFAASCAgBOTzgTEX0SNjBlLLnGhqL2lf+eBpW4t0WQ
# LxsygDPaj5fb92y68J8f0AMVhgnXrn2mOi3UJlPECVcNJgDIvrKFePygJc0yj1D9
# RDTZ1Naj2i9Sh7VhQ55TzIOD1dEINr/OgaPpohavB0DUx8GmPD6e5gV7++9F01jd
# HLiETg0/bRYb2yqhdF4i4dVbZTEjwmb3qX6O3zIZ95rAQ8mwtJkYHXD6kJ761Ois
# X+VkS9wZ4y1/YN7R7bMTZw3cOpGVFJprwY+LdNrXmAt18FouQutIboBAUr1IhjuK
# lmAaBU8A0OLiPS8GihLgcJfWI9zylGDKrzO5VMEoH61fLqwvO46mok5NUt8hZRcc
# 37sfTdnCf08VqW4s4vfS8d7RkbZRJrNrvsf9mih4J3x2JrSyQ+pfeYtB6vNShp7X
# bc44kS45MuaUqWArPCX7yfeUhxwnSDib99wzMqZ894pXK9cxw5kG8UYF9b2iaAK6
# Cxqc/z3lvuvZLagQ7utTzbs258SKpmpVPcEXUh2zyxtZAf/PwderFzBzB2uTflfd
# kS76tyf7xlqvI3XfDs0fkYEp7Sv4m2rh1ZKqdfiII4VEDH4+aLXMt51c9DGR2fxz
# ZYo9ZSPO+wFQ6DGOeNdY0HcIHUM8OftWoxFmutZyFLK1/lQXwzma01YqV9OO2yiN
# VtU9khabvw==
# SIG # End signature block
