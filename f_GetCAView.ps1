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
                                'CommonName',
                                'SerialNumber',
                                'CertificateHash',
                                'CertificateTemplate'
                            )
                        }

                        'Pending'
                        {
                            $CaView.SetRestriction([CV_COLUMN]::QUEUE_DEFAULT, 0, 0, 0)

                            $ResultColumns =
                            (
                                'Request.RequestID',
                                'Request.CommonName',
                                'Request.SubmittedWhen',
                                'CommonName',
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
                                'CommonName',
                                'CertificateTemplate'
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
                                'Request.RevokedWhen',
                                'Request.RevokedReason',
                                'CommonName',
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
# MIIeuAYJKoZIhvcNAQcCoIIeqTCCHqUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCew6LLudAvfY5t
# EIkm0s0PwqMjyP/wug3A/x72tkCtdqCCGBQwggUHMIIC76ADAgECAhB0XMs0val9
# mEnBo5ekK6KYMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIz
# MDkwNzE4NTk0NVoXDTI4MDkwNzE5MDk0NFowEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRw1gJO1wnpdRIbqVo1gfsnMV8
# kxOJBp/FDV1XxyN0njKwlcA6zyudii33AqXYWUojp4xPoXzBGkVuoqqZOkSXHMz5
# /OScP3fe4QEtIC6X9vSQuWvo9jaih0kLbRUEBTG2EVRiHsVyeLR3DPgSNckbGJ54
# MMtlhFPchHo/N7BpaGrUtdjd+F59hDVDaeoe6VVYPVaC5yAgUR9QkJZw69+YkET4
# S+Q09WgoCoXEnrVnnjPzLq0iN0rdSOrhuBE5CouwUwr6YgjU6pwtEoyBaRUhL2cd
# 8UXLzVUgy9+Bo6mhJUtq1ujECc6afx26wkDYMwfo4vTdIgFv8XATvrvWyO0a4ZGn
# 6eU+eS+hWoURP2iVlYPGUY555F1NzeOVwQ9v1cumIaOVB8x+TjJxLCtomqfVxgO9
# JeHcrqW/Q55Itr9VBGUSk6a20oEQj94UwrvoNmkbEW+/XE6DWmHf7TWEJug5d4+7
# 2pI2TmGcisERv16qSzevlkN+uUTCMVSF32Qt7ZQoRocrscj37fHVaFOA1EpbMrOp
# RwX1pWWkNBGmWptQwkTMzHNFQiTTU0OrDjqCNRh63pWcg+qdAB7ZstaoMx4vdfo/
# twAfHDTnI403nUyrIEV1gLUyJ5i5Tgw6gh8g3ozq8Qaftq+PD1rhel+ByG23LZ42
# AhGD4q4ndfG13VEONQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUWNAE
# eD3ij461l5HFCgfSYoXMwCkwDQYJKoZIhvcNAQELBQADggIBAFKCUuzQ8KfuDfqI
# ZG+peeD9+r7qcvdlIt4tRdIOgVcqEncrrAVKIcEm0Fi1Zzs6cchsiDUUUUCLkYg/
# nowzCY3g2hjQOsE3QaWHgmr+WG6JqHnOz/2/9pS+3C8EPg1VfQb/Am5G5fr3tRBm
# u2RaeKcHjoEw9T6ASDVy2fRXjNDd9rOtyYmoP3EjAqU5ey/E4A7k4nnW5x2y5sPp
# CQlr77hsZ3keGgLz87XybHPphhqA6ddYk5vJuTB2QML0xSPLnBk0C/jwORQz44Ct
# t8zdml9wBVOcOt+7Omg4pORx2Bs37hVckL+XLUP3x/4ikQ7DVQi1fweDrtZ9T2xd
# whj5+CHMc8cXzri+nYX8bvmLTYyip5Gl47eC7C6bcNsoKQq2zlLVBecTumZ6p7hT
# n3mMJWEQt4HqJ+u+PS6VKU5TkYS3A1jlUvRPdwd6AGa1BcV9ChPq9ugXqb0juRWU
# oZPhYjwz9RBgJDZk/cdON1Ie31RwmyUYyoPGFuQYsfj0RI/mCFtF12WXbh2zDR0X
# 3qU4gSaEHTVQ0jPjROietordyS4l2euH/Z8dhvJwYeOSjCIxQlBqKFtkFEq8EeGs
# zs65D3oz2DwaTZEIip1fSU7yfbJLx+fMShZ7wVXATluADk3CXqJh2izO5tiCH6yJ
# Ux7YQVpSHQNdeltDcnGMwZ7mpUrXMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBsIwggSq
# oAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# MzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1w
# IDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjU0WHHYOOW6w+
# VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIVWMGpkxGnzaqyat0QKYoeYmNp01ic
# NXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzBl5S0pVCB8s/LB6YwaMqDQtr8
# fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5xXsQGmjzwxS55DxtmUuPI1j5f2kPT
# hPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr4HhZl+NEK0rVlc7vCBfqgmRN
# /yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUdvJscsrdf3/Dudn0xmWVHVZ1KJC+s
# K5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcBkQ8ctVHNqkxmg4hoYru8QRt4
# GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02kefGRNnQ/fztFejKqrUBXJs8q818Q7
# aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk1nXNjxJ2VqUk+tfEayG66B80
# mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhvltXhEBP+YUcKjP7wtsfVx95sJPC/
# QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPsCvERLmTgyyIryvEoEyFJUX4GZtM7
# vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQD
# AgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9z
# KXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T5+/N0GSh1VapZTGj3tXjSTBaBgNV
# HR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEF
# BQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1PijxonNgl/8ss5M3qXSKS7IwiAqm4
# z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09SI64a7p8Xb3CYTdoSXej65CqEtcn
# hfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5j9smViuw86e9NwzYmHZPVrlSwrad
# OKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXTUOREEr4gDZ6pRND45Ul3CFohxbTP
# mJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08zjdSNd311RaGlWCZqA0Xe2VC1UIyv
# Vr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9NUvPJYCHEVkft2hFLjDLDiOZY4rbb
# PvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg21Llyln6XeThIX8rC3D0y33XWNmda
# ifj2p8flTzU8AL2+nCpseQHc2kTmOt44OwdeOVj0fHMxVaCAEcsUDH6uvP6k63ll
# qmjWIso765qCNVcoFstp8jKastLYOrixRoZruhf9xHdsFWyuq69zOuhJRrfVf8y2
# OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP845VJa1qwXIiNO9OzTF/tQa/8H
# dx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywGRu9BHvDwX+Db2a2QgESvgBBBijGC
# BfowggX2AgEBMCQwEDEOMAwGA1UEAwwFSjBON0UCEHRcyzS9qX2YScGjl6Qropgw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgvLo3+HxrwyNI20CnALVjiYcQCQEpJRXUV9kZ
# pB7fnwcwDQYJKoZIhvcNAQEBBQAEggIAbo+QBssiYrLAUrSUxMyR8kRN80MtGvjl
# 2T/sH5XoZpC+FLbnMKbrCrDx3rwezni2R6OJbU8O/KuvkvCfyZ8queSIa+L4Q2JD
# KpOYB6IfZzIlWLs2F73qXywYsBIzW6ncuLB8OU5zADP+snQsEkXR3XXvwLW5uZYC
# z+e8YWYmaKSaNj47jPT3zrfcgtMCAWV20zeR2aLFUm3RdMIOXm1ydhWqVhirbYIl
# mHBg1W4RL/cSddxWXn9z+4LQttQXciTJvTdPH6Wdqw836jEKmK6f/6nffjRltdvk
# 8jUt7COpfsYwE2Cr17dIUjyBzb/muAAb+Oilx4lDKZpfi9yfwVay249qD9qEt5V3
# l6Ti+bOlcQ23L7fcLMTxjGjEl3O5nvf/yXnIYLak3QbBx+wLpb5RYJbNhDoxvS7q
# NKCdFeMVqLg28NaqjG2r9vHcIduy20NpWh2iDm1oWE5foUYtIk5b5ItFTe02ZLXz
# IFafdFgnpfwxrdHglDxERMmW7TPrz8nHXgrtnkTO+IkkiCPg6zVsyb0gFJALyLRC
# kOBBqZzsNWTdmBPm/vty8M0mEI5BIDH9NBluprf2V3j3NgqkzE5fQvF9ahgBYfY3
# EDaxztPQdZBRkIIzKoh+wUBBZOa2t/YJmdKEfUqsm3DirjRp8i34/Z1r/IZmZnvW
# 07HUGAFrp7qhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAF
# RK/zlJ0IOaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMxMDMwMTQwNjQ2WjAvBgkqhkiG
# 9w0BCQQxIgQgPpmOAqr9z+SHcRV4UmsHMEnZ06wK3GmIPsR3hnGLRb0wDQYJKoZI
# hvcNAQEBBQAEggIAkcCP0cPsdMM9w4hN4KGlUjyN64o2w+LfOeGp5fI2NHm7bLC4
# Ax9CGkgLJ5MyAYoF6TCiGzGy3d3Eg/yrlpHiruu7hwPKlI2h2PaUgk6QX0NVsEKl
# VVsMb1+LzJICdCBDPEM5X/RKOJASUmKDhWbKywGJ2jwy8bUOxeQA/u0qwAaYv70O
# 3eS/P4iM6obVSSdvnDdMfrythbsR0dGNj7JMJOVJOQRtO63F87kTGUGAoZMl5Kl4
# NY6y16UyFfS0vIr52sYT7VxTCZlktxjoHWys77Q96RAOLx/ONcgXZBvwQbbcm0mf
# xojYnY/9muec2QH//yy8aW2Vb5zvhmcDY0WI8TFQ4IfgXRCoSN8YwOwr1EX6wxHK
# 1S5aMogJDpA/s1Z8nWADBSi6yCDNZw/Tq3/67lrTR/cpgA9BCK4+B/WNJiUYZoiO
# dY8hi74aaSb5/fFrlE82me/J0TxGN8fs+iWG/eaOz8Bo/bYu0NH6uCWvc3rB+UC+
# g6Gzk67j1XO9UEW1OK8dgk+ChnSYzoJUT+Uz2ScUsnVbbhJJ0yjtV1zF4zWlFIov
# HAFJluFkJy9j2UOdAU1sA9tGaDvcG2nhbIoX3YPb+6UCjxBDpwnBAVQUC2JJOYsC
# 74o1ePw96vKnjKSVHht/yvR8rBZpTPkCw6V5E2KxbNWjMWMsSg4tGPhVUHQ=
# SIG # End signature block
