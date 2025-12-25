namespace com.etsoo.AliAmapApi.Dto
{
    /// <summary>
    /// Amap autocomplete response
    /// 高德地图自动填充响应
    /// </summary>
    public record AmapAutocompleteResponse
    {
        /// <summary>
        /// 访问状态值的说明，如果成功返回"ok"，失败返回错误原因
        /// </summary>
        public required string Info { get; init; }

        /// <summary>
        /// 建议提示列表
        /// </summary>
        public IEnumerable<AmapPlaceTip>? Tips { get; init; }
    }
}
