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

namespace WebAppSamples.Infrastructure.TagHelpers;

/// <summary>
/// https://www.davepaquette.com/archive/2017/11/05/authorize-tag-helper.aspx
/// https://github.com/dpaquette/TagHelperSamples/blob/master/TagHelperSamples/src/TagHelperSamples.Authorization/AuthorizeTagHelper.cs
/// </summary>
[HtmlTargetElement(Attributes = "asp-authorize")]
[HtmlTargetElement(Attributes = "asp-authorize,asp-policy")]
[HtmlTargetElement(Attributes = "asp-authorize,asp-roles")]
[HtmlTargetElement(Attributes = "asp-authorize,asp-authentication-schemes")]
public class AuthorizeTagHelper : TagHelper, IAuthorizeData
{
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly IPolicyEvaluator _policyEvaluator;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthorizeTagHelper(IHttpContextAccessor httpContextAccessor, IAuthorizationPolicyProvider policyProvider, IPolicyEvaluator policyEvaluator)
    {
        _httpContextAccessor = httpContextAccessor;
        _policyProvider = policyProvider;
        _policyEvaluator = policyEvaluator;
    }

    /// <summary>
    /// Gets or sets the policy name that determines access to the HTML block.
    /// </summary>
    [HtmlAttributeName("asp-policy")]
    public string Policy { get; set; }

    /// <summary>
    /// Gets or sets a comma delimited list of roles that are allowed to access the HTML  block.
    /// </summary>
    [HtmlAttributeName("asp-roles")]
    public string Roles { get; set; }

    /// <summary>
    /// Gets or sets a comma delimited list of schemes from which user information is constructed.
    /// </summary>
    [HtmlAttributeName("asp-authentication-schemes")]
    public string AuthenticationSchemes { get; set; }

    public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
    {
        var policy = await AuthorizationPolicy.CombineAsync(_policyProvider, new[] { this });

        var authenticateResult = await _policyEvaluator.AuthenticateAsync(policy, _httpContextAccessor.HttpContext);

        var authorizeResult = await _policyEvaluator.AuthorizeAsync(policy, authenticateResult, _httpContextAccessor.HttpContext, null);

        if (!authorizeResult.Succeeded)
        {
            output.SuppressOutput();
        }

        if (output.Attributes.TryGetAttribute("asp-authorize", out TagHelperAttribute attribute))
        {
            output.Attributes.Remove(attribute);
        }
    }
}
