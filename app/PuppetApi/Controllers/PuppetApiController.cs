using Microsoft.AspNetCore.Mvc;
using Serilog;
using Serilog.Exceptions;
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static SimpleExec.Command;
using PuppetApi.Models;
using PuppetApi.Api.WebHost.Attributes;

namespace PuppetApi.Controllers
{
    [ApiKey]
    [ApiController]
    public class PuppetApiController : ControllerBase
    {
        /// <summary>
        /// Searches and returns Puppet Hiera Values based on required input
        /// </summary>
        /// <param name="hieraSearchRequest"></param>
        /// <returns></returns>
        [Route("api/hierasearch")]
        [HttpGet]
        public async Task<IActionResult> HieraSearch([FromQuery]HieraApiQueryData hieraSearchRequest)
        {
            // Psuedo code:
            // 1. query Puppet Classifier and get env.json into json object (from string output):  https://puppet.com/docs/pe/2021.2/node_classifier_service_api.html
            // 2. extract (filter) json for environment name variables (only) into another variable
            // 3. create random name /tmp file
            // 4. then write extracted json to /tmp file
            // 5. execute puppet lookup using /tmp file and other params from GET:  https://puppet.com/docs/puppet/7/man/lookup.html
            // 6. delete /tmp file
            // 6. populate and return json containing puppet ConsoleVariables and HieraSearchValue result

            // Issues:
            // 1. Console variables returned as escaped values and want to output non-escaped string, however, wrtten to disk is non-escaped -- manual hack on line 126

            const string envjsonEndpoint = "https://localhost:4433/classifier-api/v1/groups";
            HieraData hieraData = new HieraData();
            hieraSearchRequest.Branch = hieraSearchRequest.Branch.Replace(".", "_");  // Convert periods to underscores for Puppet Code Deploy branch naming convention
            Log.Information($"GET query data: Environment={hieraSearchRequest.Environment}, Branch={hieraSearchRequest.Branch}, HieraSearchKey={hieraSearchRequest.HieraSearchKey}");
            /////////////////////////////////////////////////////
            /// Query Puppet Classifier for Console Variables ///
            /////////////////////////////////////////////////////
            var handler = new HttpClientHandler();
            string envjsonResult = "";
            // Add Puppet Classifier client certs to handler, cacert is not needed
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(new X509Certificate2(X509Certificate2.CreateFromPemFile("/etc/puppetlabs/puppet/ssl/certs/puppetmaster.dev.rph.int.pem", "/etc/puppetlabs/puppet/ssl/private_keys/puppetmaster.dev.rph.int.pem").Export(X509ContentType.Pfx)));
            handler.ServerCertificateCustomValidationCallback = (requestMessage, certificate, chain, policyErrors) => true;
            using (var httpClient = new HttpClient(handler))
            {
                using (var request = new HttpRequestMessage(new HttpMethod("GET"), envjsonEndpoint))
                {
                    Log.Debug($"Querying Puppet Classifier endpoint: {envjsonEndpoint}...");
                    var httpResponse = await httpClient.SendAsync(request);
                    if (httpResponse.IsSuccessStatusCode)
                    {
                        envjsonResult = await httpResponse.Content.ReadAsStringAsync();
                    }
                    else
                    {
                        Log.Error("Puppet Classifier query returned with error, is it available?");
                        return StatusCode(500, "Puppet Classifier query returned with error or timed out.");
                    }
                }
            }
            /////////////////////////////////////////////
            /// Parse and Filter JSON for Environment ///
            /////////////////////////////////////////////
            string tmpfile = "/tmp/" + Path.GetRandomFileName();
            if (String.IsNullOrEmpty(envjsonResult))
            {
                Log.Error("Puppet Classifier result returned empty string, is there a problem with it?");
                return StatusCode(500, "Puppet Classifier result returned empty string.");
            }
            else
            {
                // Parse result into Jarray
                JArray envjsonParse = JArray.Parse(envjsonResult);
                // Filter JSON to specific environment Console variables
                Log.Information($"Begin JSONPath filter on envjson using environment {hieraSearchRequest.Environment}...");
                // Parent lookup
                string envjsonParent = envjsonParse.SelectToken("$..[?(@.name == '" + hieraSearchRequest.Environment + "')].parent", false)?.ToObject<string>();
                Log.Debug($"Parent environment: {envjsonParent}");
                // Prepare the JPath strings outside of the SelectTokens calls to avoid string concatenation inside the loop
                string parentJPath = "$..[?(@.id == '" + envjsonParent.Replace("'", "\\'") + "')].variables";
                string childJPath = "$..[?(@.name == '" + hieraSearchRequest.Environment.Replace("'", "\\'") + "')].variables";
                // Select tokens using the prepared JPaths
                IEnumerable<JToken> envjsonParentTokens = envjsonParse.SelectTokens(parentJPath, false);
                IEnumerable<JToken> envjsonChildTokens = envjsonParse.SelectTokens(childJPath, false);
                // Safely get the first element and convert to JObject if available, else create an empty JObject
                if (envjsonParentTokens.FirstOrDefault() is not JObject envParent)
                {
                    envParent = new JObject();
                }
                if (envjsonChildTokens.FirstOrDefault() is not JObject envChild)
                {
                    envChild = new JObject();
                }
                // Merge (union) both environments
                envParent.Merge(envChild, new JsonMergeSettings
                {
                    MergeArrayHandling = MergeArrayHandling.Union
                });
                // Convert back to JToken
                JToken envjsonTokens = JToken.FromObject(envParent);
                Log.Information($"Number of variables matched: {envjsonTokens.Count()}");
                if (!envjsonTokens.Any())
                {
                    Log.Error("Puppet Classifier result returned no values while trying to filter, is Environment query data correct?");
                    return StatusCode(500, "Puppet Classifier result returned no values while trying to match on filter, check for valid environment name.");
                }
                Log.Information($"Puppet Console Variables for environment {hieraSearchRequest.Environment}: {envjsonTokens.ToString()}");
                Log.Debug($"Creating temp file: {tmpfile} with Puppet Console variables...");
                await System.IO.File.WriteAllTextAsync(tmpfile, envjsonTokens.ToString());
            }
            //////////////////////////////////////////
            // Execute Puppet lookup CMD for result //
            //////////////////////////////////////////
            Log.Debug($"Executing Puppet lookup CMD...");
            int exitCode = 0;
            var (lookupResult, lookupError) = await ReadAsync("/usr/local/bin/puppet",
                new[] { "lookup", "--merge", "deep", "--merge-hash-arrays", "--render-as", "json", "--environment", hieraSearchRequest.Branch, "--facts", tmpfile, hieraSearchRequest.HieraSearchKey },
                handleExitCode: code => (exitCode = code) < 2);
            try
            {
                Log.Debug($"Deleting temp file {tmpfile}");
                System.IO.File.Delete(tmpfile);
            } 
            catch (IOException ioException)
            {
                Log.Warning(ioException, "Can't delete temp file");
            }
            if (exitCode != 0)
            {
                Log.Error($"Puppet lookup error: {lookupError}");
                return StatusCode(500, $"Puppet lookup error on {hieraSearchRequest.HieraSearchKey}");
            }
            if (String.IsNullOrEmpty(lookupResult))
            {
                Log.Error("Puppet lookup CMD returned null or empty string, was search key valid?");
                return NotFound("Puppet lookup CMD returned null or empty string, use valid puppet Hiera key.");
            }
            hieraData.HieraSearchValue = lookupResult.TrimEnd('\n');
            Log.Information($"Puppet lookup returned from \"{hieraSearchRequest.HieraSearchKey}\" query: {hieraData.HieraSearchValue}");
            // Need to return values in JSON manually due to getting only raw results from Puppet lookup
            return Ok("{ \"HieraSearchValue\": " + hieraData.HieraSearchValue + " }");
        }
        /// <summary>
        /// Execute "puppet" command with querystring parameters on puppet master. 
        /// Include all commands and arguments to be executed following the "puppet" cmd
        /// </summary>
        /// <param name="PuppetCMDRequest"></param>
        /// <returns></returns>
        [Route("api/puppet-cmd")]
        [HttpGet]
        public async Task<IActionResult> PuppetCMD([FromQuery] string PuppetCMDRequest)
        {
            // Psuedo code:
            // 1. Execute "puppet" command with querystring data, parsing and limited data validation
            // 2. Forbid multi-command injection
            // 3. Return status of command

            Log.Information($"GET query data: {PuppetCMDRequest}");
            //////////////////////////
            /// Execute PuppetCMD  ///
            //////////////////////////
            Log.Information($"Executing puppet CMD...");
            Log.Information($"QueryString: {PuppetCMDRequest}");
            if (new string[] { ";", "&&", "||" }.Any(s => PuppetCMDRequest.ToLower().Contains(s)))
            {
                Log.Warning("WARNING: Forbidden to execute multiple commands");
                return StatusCode(501, "Forbidden to execute multiple commands");
            }
            string[] QueryString = PuppetCMDRequest.Split(' ');
            int exitCode = 0;
            var (cmdResult, cmdError) = await ReadAsync("/usr/local/bin/puppet",
                QueryString,
                handleExitCode: code => (exitCode = code) < 2);
            if (exitCode != 0)
            {
                Log.Error($"puppet RESULT: {cmdResult}");
                Log.Error($"puppet ERROR: {cmdError}");
                return StatusCode(500, $"RESULT returned from: \"puppet {PuppetCMDRequest}\":\n{cmdResult}\nERROR: {cmdError}\n");
            }
            if (System.String.IsNullOrEmpty(cmdResult))
            {
                Log.Error("puppet returned null or empty string.");
                return NotFound("puppet returned null or empty string.");
            }
            Log.Information($"puppet RESULT: {cmdResult}");
            return Ok(cmdResult);
        }
        /// <summary>
        /// Execute "puppetserver ca" command with querystring parameters on puppet master. 
        /// Include all commands and arguments to be executed following the "puppetserver ca" cmd
        /// </summary>
        /// <param name="PuppetServerCARequest"></param>
        /// <returns></returns>
        [Route("api/puppetserver-ca-cmd")]
        [HttpGet]
        public async Task<IActionResult> PuppetServerCMD([FromQuery] string PuppetServerCARequest)
        {
            // Psuedo code:
            // 1. Execute "puppetserver ca" command with querystring data, parsing and limited data validation
            // 2. Forbid multi-command injection
            // 3. Return status of command

            Log.Information($"GET query data: {PuppetServerCARequest}");
            ///////////////////////////////
            /// Execute PuppetServerCMD ///
            ///////////////////////////////
            Log.Information($"Executing puppetserver ca CMD...");
            Log.Information($"QueryString: {PuppetServerCARequest}");
            if (new string[] { "setup", "migrate", "import" }.Any(s => PuppetServerCARequest.ToLower().Contains(s)))
            {
                Log.Warning("WARNING: Forbidden to setup/migrate/import puppet master CA");
                return StatusCode(501, "Forbidden to setup/migrate/import puppet master CA");
            }
            if (new string[] { ";", "&&", "||" }.Any(s => PuppetServerCARequest.ToLower().Contains(s)))
            {
                Log.Warning("WARNING: Forbidden to execute multiple commands");
                return StatusCode(501, "Forbidden to execute multiple commands");
            }
            //string[] QueryString = PuppetServerCARequest.Split(' ');
            int exitCode = 0;
            var (cmdResult, cmdError) = await ReadAsync("/opt/puppetlabs/bin/puppetserver",
                $"ca {PuppetServerCARequest}",
                handleExitCode: code => (exitCode = code) < 2);
            if (exitCode != 0)
            {
                Log.Error($"puppetserver ca RESULT: {cmdResult}");
                Log.Error($"puppetserver ca ERROR: {cmdError}");
                return StatusCode(500, $"RESULT returned from: \"puppetserver ca {PuppetServerCARequest}\":\n{cmdResult}\nERROR: {cmdError}\n");
            }
            if (System.String.IsNullOrEmpty(cmdResult))
            {
                Log.Error("puppetserver ca returned null or empty string.");
                return NotFound("puppetserver ca returned null or empty string.");
            }
            Log.Information($"puppetserver ca RESULT: {cmdResult}");
            return Ok(cmdResult);
        }
    }
}
