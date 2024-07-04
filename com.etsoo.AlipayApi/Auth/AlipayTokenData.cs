namespace com.etsoo.AlipayApi.Auth
{
    /// <summary>
    /// Alipay OAuth2 token data
    /// 支付宝OAuth2令牌数据
    /// </summary>
    public record AlipayTokenData
    {
        /// <summary>
        /// Access token. Use this token to call the authorization class interface
        /// 访问令牌。通过该令牌调用需要授权类接口
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// The remaining lifetime of the access token in seconds
        /// 访问令牌的剩余生存时间（以秒为单位）
        /// </summary>
        public required int ExpiresIn { get; init; }

        /// <summary>
        /// Alipay user unique identifier
        /// 支付宝用户唯一标识
        /// </summary>
        public required string OpenId { get; init; }

        /// <summary>
        /// Refresh token. This token can be used to refresh access_token
        /// 刷新令牌。通过该令牌可以刷新access_token
        /// </summary>
        public required string RefreshToken { get; init; }

        /// <summary>
        /// The validity period of the refresh token in seconds
        /// 刷新令牌的有效时间，单位是秒
        /// </summary>
        public required int ReExpiresIn { get; init; }
    }
}
