# PuppetHieraApi

## Restful WebApi to query Hiera data from Puppet master

## Sample Powershell query:

    \[System.Net.ServicePointManager\]::SecurityProtocol = \[System.Net.SecurityProtocolType\]::Tls12
    $headers = @{'ApiKey' = '424e8d26-8d0b-4667-bf51-43d182cc3a06'}
    $endpointUri = "https://puppetmaster.dev.rph.int:5001/api/PuppetHieraSearch?Environment=QA-P1-CS&Branch=2022_4&HieraSearchKey=profile::admin_app_iis_api::appsettings"
    $a = Invoke-RestMethod -SkipCertificateCheck -Uri $endpointUri -Method Get -Headers $headers
