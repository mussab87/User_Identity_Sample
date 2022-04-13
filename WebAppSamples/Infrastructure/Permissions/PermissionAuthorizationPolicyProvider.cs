/* THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
 * We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
 * (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; and
 * (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
 * (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
 */

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using WebAppSamples.Infrastructure.Constants;

namespace WebAppSamples.Infrastructure.Permissions
{
    public class PermissionAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        public PermissionAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
        {
        }

        public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (!policyName.StartsWith(AuthorizePermissionConstants.PolicyPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return await base.GetPolicyAsync(policyName);
            }

            var claimName = policyName.Substring(AuthorizePermissionConstants.PolicyPrefix.Length);

            var policy = new AuthorizationPolicyBuilder()
                .RequireClaim(AuthorizePermissionConstants.ClaimType, claimName)
                .Build();

            return policy;
        }
    }
}
