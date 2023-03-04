#requires -version 6.2
<#
    .SYNOPSIS
        This command will read a CSV file generated from Export-AzSentinelAnlyticsRuleTemplatesToCSV.ps1 and create
        the rules from the selected template entries. It will look for an "X" in the first column
        of each row in the file and if found it will generate a new Analytic rule from the
        selected template.
    .DESCRIPTION
        This command will read a CSV file generated from Export-AzSentinelAnlyticsRuleTemplatesToCSV.ps1 and create
        the rules from the selected template entries. It will look for an X in the first column
        of each row in the file and if found it will generate a new Analytic rule from the
        selected template.
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName
        Enter the file name to read.  Defaults to "ruletemplates.csv"  
    .PARAMETER OutputfileName
        Enter the file name to store the results.  Defaults to "rulesOutput.csv"  
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 3 March 2023
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname"
        In this example you will read the file named "ruletemplates.csv" that contains all the rules to create and output to
        "rulesOutput.csv"
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"
        In this example you will read the file named "test.csv" that contains all the rules to create and output to
        "rulesOutput.csv"
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname" -outputFileName "output"
        In this example you will read the file named "ruletemplates.csv" that contains all the rules to create and output to
        "output.csv"
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test" -outputFileName "output"
        In this example you will read the file named "test.csv" that contains all the rules to create and output to
        "output.csv"
   
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [string]$FileName = "rulestemplate.csv",

    [string]$OutputFileName = "rulesOutput.csv"
)

Function New-AzSentinelAnalyticsRulesFromCSV ($workspaceName, $resourceGroupName, $filename, $outputFileName) {
    #Set up the authentication header
    $context = Get-AzContext
    $azureProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azureProfile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    $SubscriptionId = $context.Subscription.Id

    #Load all the rule templates so we can copy the information as needed.
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2023-02-01"
    $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    #Load the rule templates from solutions
    $solutionURL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    $query = @"
  Resources 
  | where type =~ 'Microsoft.Resources/templateSpecs/versions' 
  | where tags['hidden-sentinelContentType'] =~ 'AnalyticsRule' 
  and tags['hidden-sentinelWorkspaceId'] =~ '/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)' 
  | extend version = name 
  | extend parsed_version = parse_version(version) 
  | extend resources = parse_json(parse_json(parse_json(properties).template).resources) 
  | extend metadata = parse_json(resources[array_length(resources)-1].properties)
  | extend contentId=tostring(metadata.contentId) 
  | summarize arg_max(parsed_version, version, properties) by contentId 
  | project contentId, version, properties
"@
    $body = @{
        "subscriptions" = @($SubscriptionId)
        "query"         = $query
    }
    $solutionTemplates = Invoke-RestMethod -Uri $solutionURL -Method POST -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)

    #Create the object to store the output
    $outputObject = New-Object system.Data.DataTable
    [void]$outputObject.Columns.Add('Name', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Source', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Status', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('ErrorMessage', [string]::empty.GetType() )
    
    #Load the file that contains all the rules
    $fileContents = Import-Csv $FileName

    #Iterate through all the rows in the file
    $fileContents | ForEach-Object {
        #Read the selected column (the first column in the file)
        $selected = $_.Selected

        #If this entry has been marked to be used...
        if ($selected.ToUpper() -eq "X") {
            $name = $_.Id
            $kind = $_.Kind
            $displayName = $_.Name
            $Source = $_.Source

            #If the rule is coming from Sentinel, check to see if the rule is coming from Sentinel
            #(And it better!)
            if ($source -eq "Sentinel") {
                $template = $results | Where-Object -Property "name" -EQ $name
            }
            #Otherwise, read the rule information from the solution
            else {
                $template = $solutionTemplates.properties.template.resources | Where-Object -Property "name" -EQ $name
            }

            #If we found a match....we better!
            if ($null -ne $template) {
                $body = ""
                #Due to how the solution returns the rule template information, I created a new variable
                #to hold the information so I won't have to do a lot of if statements further on
                if ($source -eq "Sentinel") {
                    $ruleTemplate = $template.properties
                }
                else {
                    #Using the index due to the way that the solution returns the information
                    $ruleTemplate = $template.properties.template.resources.properties[0]
                }

                #The rules require a duration, but not all of the rule templates have this field
                #typically the older rule templates.   In any case, if there is no duration
                #set one.
                $suppressionDuration = $ruleTemplate.suppressionDuration
                If ($null -eq $suppressionDuration) {
                    $suppressionDuration = "PT5H"
                }

                #Same with the suppression enabled (see above)
                $suppressionEnabled = $ruleTemplate.suppressionEnabled
                if ($null -eq $suppressionEnabled) {
                    $suppressionEnabled = $false
                }

                #There is some weirdness where the Entity mappings is saved as {} rather than
                #null.   The count -eq 0 is used to check for this and if it is true, set to null
                $entityMappings = $ruleTemplate.entityMappings
                if ($entityMappings.count -eq 0) {
                    $entityMappings = $null
                }
                
                #Depending on the type of alert we are creating, the body has different parameters
                switch ($kind) {
                    "MicrosoftSecurityIncidentCreation" {  
                        $body = @{
                            "kind"       = "MicrosoftSecurityIncidentCreation"
                            "properties" = @{
                                "enabled"       = "true"
                                "productFilter" = $ruleTemplate.properties.productFilter
                                "displayName"   = $ruleTemplate.displayName
                            }
                        }
                    }
                    "Scheduled" {
                        $body = @{
                            "kind"       = "Scheduled"
                            "properties" = @{
                                "enabled"               = "true"
                                "alertRuleTemplateName" = $name
                                "displayName"           = $ruleTemplate.displayName
                                "description"           = $ruleTemplate.description
                                "severity"              = $ruleTemplate.severity
                                "tactics"               = $ruleTemplate.tactics
                                "techniques"            = $ruleTemplate.techniques
                                "query"                 = $ruleTemplate.query
                                "queryFrequency"        = $ruleTemplate.queryFrequency
                                "queryPeriod"           = $ruleTemplate.queryPeriod
                                "triggerOperator"       = $ruleTemplate.triggerOperator
                                "triggerThreshold"      = $ruleTemplate.triggerThreshold
                                "suppressionDuration"   = $suppressionDuration
                                "suppressionEnabled"    = $suppressionEnabled
                                "eventGroupingSettings" = $ruleTemplate.eventGroupingSettings
                                "templateVersion"       = $ruleTemplate.version
                                "entityMappings"        = $entityMappings
                            }
                        }
                    }
                    "MLBehaviorAnalytics" {
                        if ($ruleTemplate.status -eq "Available") {
                            $body = @{
                                "kind"       = "MLBehaviorAnalytics"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $ruleTemplate.name
                                }
                            }
                        }
                    }
                    #I don't think this is needed anymore since this is the one rule that is enabled by default
                    #but, as a developer, I hate removing code. 
                    "Fusion" {
                        if ($ruleTemplate.status -eq "Available") {
                            $body = @{
                                "kind"       = "Fusion"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $ruleTemplate.name
                                }
                            }
                        }
                    }
                    "NRT" {
                        if ($ruleTemplate.status -eq "Available") {
                            $body = @{
                                "kind"       = "NRT"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $name
                                    "displayName"           = $ruleTemplate.displayName
                                    "description"           = $ruleTemplate.description
                                    "severity"              = $ruleTemplate.severity
                                    "tactics"               = $ruleTemplate.tactics
                                    "techniques"            = $ruleTemplate.techniques
                                    "query"                 = $ruleTemplate.query
                                    "suppressionDuration"   = $suppressionDuration
                                    "suppressionEnabled"    = $suppressionEnabled
                                    "eventGroupingSettings" = $ruleTemplate.eventGroupingSettings
                                    "templateVersion"       = $ruleTemplate.version
                                    "entityMappings"        = $entityMappings
                                }
                            }
                        }
                    }
                    Default { }
                }
                #If we have created the body...
                if ("" -ne $body) {
                    #Create the GUID for the alert and create it.
                    $guid = (New-Guid).Guid
                    $errorReturn = ""
                    $status = ""
                    #Create the URI we need to create the alert.
                    $uri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertRules/$($guid)?api-version=2023-02-01"
                    try {
                        Write-Host "Attempting to create rule $($displayName)"
                        $verdict = Invoke-RestMethod -Uri $uri -Method Put -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)
                        Write-Output "Succeeded"
                        $status = "Succeeded"
                    }
                    catch {
                        #The most likely error is that there is a missing dataset. There is a new
                        #addition to the REST API to check for the existance of a dataset but
                        #it only checks certain ones.  Hope to modify this to do the check
                        #before trying to create the alert.
                        $errorReturn = $_
                        Write-Error $errorReturn
                        $status = "Error"
                    }
                    #This pauses for 5 second so that we don't overload the workspace.  This could be lower
                    Start-Sleep -Seconds 5

                    #Save the output so it can be written to a file
                    $newRow = $outputObject.NewRow()
                    $newRow.Name = $displayName
                    $newRow.Source = $Source
                    $newRow.Status = $status
                    $newRow.ErrorMessage = $errorReturn
                    [void]$outputObject.Rows.Add( $newRow )
                }
            }
            #In theory we should never get here but better safe than sorry
            else {
                Write-Host "Unable to find rule template $($displayName).  Should be a $($Source) type"
                $newRow = $outputObject.NewRow()
                $newRow.Name = $displayName
                $newRow.Source = $Source
                $newRow.Status = "Cannot Find"
                $newRow.ErrorMessage = "Unable to find rule template $($displayName).  Should be a $($Source) type"
                [void]$outputObject.Rows.Add( $newRow )
            }
        }
    }
    #Output the information to the file.  Probably don't need the sort but it doesn't hurt anything.
    $outputObject | Sort-Object -Property "Name" | Export-Csv -QuoteFields "Name", "ErrorMessage" -Path $outputFileName -Append
}

#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}
New-AzSentinelAnalyticsRulesFromCSV $WorkSpaceName $ResourceGroupName $FileName $OutputFileName

