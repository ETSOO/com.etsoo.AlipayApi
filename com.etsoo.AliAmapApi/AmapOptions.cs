namespace com.etsoo.AliAmapApi
{
    /// <summary>
    /// Amap API options
    /// 高德地图 API 选项
    /// </summary>
    public record AmapOptions
    {
        /// <summary>
        /// API key
        /// 接口密钥
        /// </summary>
        public required string ApiKey { get; set; }

        /// <summary>
        /// Private key
        /// 私钥
        /// </summary>
        public string? PrivateKey { get; set; }

        /// <summary>
        /// API base address
        /// 接口基地址
        /// </summary>
        public string BaseAddress { get; set; } = "https://restapi.amap.com/";
    }
}
