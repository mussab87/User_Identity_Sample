/* THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
 * We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
 * (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; and
 * (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
 * (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
 */

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Razor.TagHelpers;
using WebAppSamples.Infrastructure.Constants;

namespace WebAppSamples.Infrastructure.TagHelpers;

[HtmlTargetElement(Attributes = "asp-authorize-permission")]
public class AuthorizePermissionTagHelper : TagHelper, IAuthorizeData
{
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly IPolicyEvaluator _policyEvaluator;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthorizePermissionTagHelper(IHttpContextAccessor httpContextAccessor, IAuthorizationPolicyProvider policyProvider, IPolicyEvaluator policyEvaluator)
    {
        _httpContextAccessor = httpContextAccessor;
        _policyProvider = policyProvider;
        _policyEvaluator = policyEvaluator;
    }

    [HtmlAttributeName("asp-permission")]
    public string Policy { get; set; }
    public string Roles { get; set; }
    public string AuthenticationSchemes { get; set; }

    public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
    {
        Policy = $"{AuthorizePermissionConstants.PolicyPrefix}{Policy}";

        var policy = await AuthorizationPolicy.CombineAsync(_policyProvider, new[] { this });

        var authenticateResult = await _policyEvaluator.AuthenticateAsync(policy, _httpContextAccessor.HttpContext);

        var authorizeResult = await _policyEvaluator.AuthorizeAsync(policy, authenticateResult, _httpContextAccessor.HttpContext, null);

        if (!authorizeResult.Succeeded)
        {
            output.SuppressOutput();
        }

        if (output.Attributes.TryGetAttribute("asp-authorize-permission", out TagHelperAttribute attribute))
        {
            output.Attributes.Remove(attribute);
        }
    }
}
