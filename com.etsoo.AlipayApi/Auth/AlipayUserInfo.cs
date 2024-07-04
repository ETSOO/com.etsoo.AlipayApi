namespace com.etsoo.AlipayApi.Auth
{
    /// <summary>
    /// Alipay user information
    /// 支付宝用户信息
    /// </summary>
    public record AlipayUserInfo
    {
        /// <summary>
        /// Alipay user unique identifier
        /// 支付宝用户唯一标识
        /// </summary>
        public required string OpenId { get; init; }

        /// <summary>
        /// User name
        /// 用户头像地址
        /// </summary>
        public required string Avatar { get; init; }

        /// <summary>
        /// User name
        /// 用户昵称
        /// </summary>
        public string? NickName { get; init; }
    }
}
