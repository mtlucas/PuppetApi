using Microsoft.OpenApi.Models;
using System;
using System.Reflection;
using System.Collections.Generic;
using Swashbuckle.AspNetCore.Filters;
using Swashbuckle.AspNetCore.SwaggerGen;
using PuppetHieraApi.Api.WebHost.Attributes;

namespace PuppetHieraApi.Api.WebHost
{
    // Filter that will secure ApiKey Swagger Api endpoints (Padlocks)
    public class AuthenticationRequirementsOperationFilter : IOperationFilter
    {

        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            context.ApiDescription.TryGetMethodInfo(out MethodInfo methodInfo);

            if (methodInfo == null)
            {
                return;
            }

            var hasApiKeyAttribute = true;

            if (methodInfo.MemberType == MemberTypes.Method)
            {
                // NOTE: Check the controller or the method itself has ApiKeyAttribute attribute
                hasApiKeyAttribute =
                   methodInfo.DeclaringType.GetCustomAttributes(true).OfType<ApiKeyAttribute>().Any() ||
                   methodInfo.GetCustomAttributes(true).OfType<ApiKeyAttribute>().Any();
            }

            if (!hasApiKeyAttribute)
            {
                return;
            }

            // NOTE: This adds the "Padlock" icon to the endpoint in swagger, 
            //       we can also pass through the names of the policies in the List<string>()
            //       which will indicate which permission you require.
            operation.Security = new List<OpenApiSecurityRequirement>
            {
                new OpenApiSecurityRequirement()
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                                { Type = ReferenceType.SecurityScheme, Id = "ApiKey" },
                                Scheme = "ApiKeyScheme",
                                Name = "ApiKey",
                                In = ParameterLocation.Header,
                        },
                        new List<string>()
                     }
                }
            };
        }
    }
}
