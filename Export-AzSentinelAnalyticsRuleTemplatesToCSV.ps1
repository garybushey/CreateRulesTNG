#requires -version 6.2
<#
    .SYNOPSIS
        This command will generate a CSV file containing the information about all the Azure Sentinel
        Analytic rules templates.  Place an X in the first column of the CSV file for any template
        that should be used to create a rule and then call New-RulesFromTemplateCSV.ps1 to generate
        the rules.
    .DESCRIPTION
        This command will generate a CSV file containing the information about all the Azure Sentinel
        Analytic rules templates. Place an X in the first column of the CSV file for any template
        that should be used to create a rule and then call New-RulesFromTemplateCSV.ps1 to generate
        the rules.
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName
        Enter the file name to use.  Defaults to "ruletemplates"  ".csv" will be appended to all filenames
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 3 March 2023
    .EXAMPLE
        Export-AzSentinelAnalyticsRuleTemplates -WorkspaceName "workspacename" -ResourceGroupName "rgname"
        In this example you will get the file named "ruletemplates.csv" generated containing all the rule templates
    .EXAMPLE
        Export-AzSentinelAnalyticsRuleTemplates -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"
        In this example you will get the file named "test.csv" generated containing all the rule templates
   
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [string]$FileName = "rulestemplate.csv"
)
Function Export-AzSentinelAnalyticsRuleTemplatesToCSV ($workspaceName, $resourceGroupName, $filename) {

    $outputObject = New-Object system.Data.DataTable
    [void]$outputObject.Columns.Add('Selected', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Name', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('ID', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Source', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Severity', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Kind', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Description', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Tactics', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('Techniques', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('QueryFrequency', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('QueryPeriod', [string]::empty.GetType() )
    
    #Setup the header for the file
    <#    $output = "Selected,Severity,DisplayName,Kind,Data Connector,Description,Tactics,RequiredDataConnectors,RuleFrequency,RulePeriod,RuleThreshold,Status"
    $output >> $filename #>
    
    #Setup the Authentication header needed for the REST calls
    $context = Get-AzContext
    $myProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($myProfile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    $SubscriptionId = (Get-AzContext).Subscription.Id

    #Load the MS Sentinel templates so that we can copy the information as needed
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2023-02-01-preview"
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

    #Loop through all the Sentinel rules
    foreach ($result in $results) {
        $kind = $result.kind
        if ($kind -eq "Scheduled" -or ($kind -eq "NRT")) {
            #Generate the list of tactics.  Using the pipe as the 
            #delimiter since it does not appear in any data connector name
            $tactics = ""
            foreach ($tactic in $result.properties.tactics) { $tactics += $tactic + "|" }
            #If we have an entry, remove the last pipe character
            if ("" -ne $tactics) {
                $tactics = $tactics.Substring(0, $tactics.length - 1)
            }

            $techniques = ""
            foreach ($technique in $result.properties.techniques) { $techniques += $technique + "|" }
            #If we have an entry, remove the last pipe character
            if ("" -ne $techniques) {
                $techniques = $techniques.Substring(0, $techniques.length - 1)
            }

            $newRow = $outputObject.NewRow()
            $newRow.Selected = ""
            $newRow.Name = $result.properties.displayName
            $newRow.Id = $result.name
            $newRow.Source = "Sentinel"
            $newRow.Severity = $result.properties.severity
            $newRow.Kind = $result.kind
            $newRow.Description = $result.properties.description
            $newRow.Tactics = $tactics
            $newRow.Techniques = $techniques
            $newRow.QueryFrequency = $result.properties.queryFrequency
            $newRow.QueryPeriod = $result.properties.queryPeriod
            [void]$outputObject.Rows.Add( $newRow )
        }
    }

    #Loop through the Solution rules
    foreach ($result in $solutionTemplates.data) {
        #Because of how far down the properties are in a Solution rule, I create a new variable
        #rather than having to write this all out all the time.
        $template = $result.properties.template.resources
        #Using the index due to the way everything is returned.
        $kind = $template.kind[0]
        if ($kind -eq "Scheduled" -or ($kind -eq "NRT")) {
            #Generate the list of tactics.  Using the pipe as the 
            #delimiter since it does not appear in any data connector name
            $tactics = ""
            foreach ($tactic in $template.properties[0].tactics) { $tactics += $tactic + "|" }
            #If we have an entry, remove the last pipe character
            if ("" -ne $tactics) {
                $tactics = $tactics.Substring(0, $tactics.length - 1)
            }

            $techniques = ""
            foreach ($technique in $template.properties[0].techniques) { $techniques += $technique + "|" }
            #If we have an entry, remove the last pipe character
            if ("" -ne $techniques) {
                $techniques = $techniques.Substring(0, $techniques.length - 1)
            }

            $newRow = $outputObject.NewRow()
            $newRow.Selected = ""
            $newRow.Name = $template.properties[0].displayName
            $newRow.Id = $template.name
            $newRow.Source = "Solution"
            $newRow.Severity = $template.properties[0].severity
            $newRow.Kind = $kind
            $newRow.Description = $template.properties[0].description
            $newRow.Tactics = $tactics
            $newRow.Techniques = $techniques
            $newRow.QueryFrequency = $template.properties[0].queryFrequency
            $newRow.QueryPeriod = $template.properties[0].queryPeriod
            [void]$outputObject.Rows.Add( $newRow )
        }
    }
    #When we output the rules, we want to sort by the name of the rules to make sure 
    #all the rules are in alphabetical order
    $outputObject | Sort-Object -Property "Name" | Export-Csv -QuoteFields "Name", "Description" -Path $fileName -Append
}


#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}
Export-AzSentinelAnalyticsRuleTemplatesToCSV $WorkSpaceName $ResourceGroupName $FileName 
