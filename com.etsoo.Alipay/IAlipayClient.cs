﻿using com.etsoo.AlipayApi.Auth;
using com.etsoo.ApiModel.Auth;
using com.etsoo.Utils.Actions;
using Microsoft.AspNetCore.Http;

namespace com.etsoo.AlipayApi
{
    /// <summary>
    /// Alipay client interface
    /// 支付宝客户端接口
    /// </summary>
    public interface IAlipayClient : IAuthClient
    {
        /// <summary>
        /// Create access token from authorization code
        /// 从授权码创建访问令牌
        /// </summary>
        /// <param name="code">Authorization code</param>
        /// <returns>Token data</returns>
        ValueTask<AlipayTokenData?> CreateTokenAsync(string code);

        /// <summary>
        /// Get user info
        /// 获取用户信息
        /// </summary>
        /// <param name="tokenData">Token data</param>
        /// <returns>Result</returns>
        ValueTask<AlipayUserInfo?> GetUserInfoAsync(AlipayTokenData tokenData);

        /// <summary>
        /// Refresh the access token with refresh token
        /// 用刷新令牌获取访问令牌
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <returns>Result</returns>
        Task<AlipayTokenData?> RefreshTokenAsync(string refreshToken);

        /// <summary>
        /// Validate auth callback
        /// 验证认证回调
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="state">State</param>
        /// <returns>Action result & Token data</returns>
        Task<(IActionResult result, AlipayTokenData? tokenData)> ValidateAuthAsync(HttpRequest request, string state);
    }
}
