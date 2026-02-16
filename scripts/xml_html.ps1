PARAM
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$XmlPath,
     
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$XslPath,
     
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$HtmlOutput
)
 
try
{

    $Xslt = New-Object System.Xml.Xsl.XslCompiledTransform
    
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Parse

    $reader = [System.Xml.XmlReader]::Create($XmlPath, $settings)
    $writer = New-Object IO.StreamWriter($HtmlOutput)

if ($XslPath.StartsWith("http")) {

    $resolver = New-Object System.Xml.XmlUrlResolver
    $xsltSettings = New-Object System.Xml.Xsl.XsltSettings($true, $true)
    $Xslt.Load($XslPath, $xsltSettings, $resolver)
}
else {
    
    $Xslt.Load($XslPath)
}

    $Xslt.Transform($reader, $null, $writer)
    $writer.Close()

}

catch
{
    Write-Host $_.Exception -ForegroundColor Red
}
