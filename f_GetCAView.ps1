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

        [Parameter(ParameterSetName='Request')]
        [Parameter(ParameterSetName='Extension')]
        [Parameter(ParameterSetName='Attribute')]
        [Parameter(ParameterSetName='Crl')]
        [Array]$Properties,

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

            #############
            # Get schema
            #############

            if ($GetSchema.IsPresent)
            {
                Write-Output -InputObject (Get-AllColumns)
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
