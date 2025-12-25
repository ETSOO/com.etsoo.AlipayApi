using System.Text.Json.Serialization;

namespace com.etsoo.AliAmapApi.Dto
{
    /// <summary>
    /// Amap place response
    /// 高德地图地址响应
    /// </summary>
    public record AmapPlaceResponse
    {
        /// <summary>
        /// 单次请求返回的实际 poi 点的个数
        /// </summary>
        [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
        public int Count { get; init; }

        /// <summary>
        /// 访问状态值的说明，如果成功返回"ok"，失败返回错误原因
        /// </summary>
        public required string Info { get; init; }

        /// <summary>
        /// 返回状态说明,10000代表正确
        /// </summary>
        public required string Infocode { get; init; }

        /// <summary>
        /// 地址列表
        /// </summary>
        public IEnumerable<AmapPlace>? Pois { get; init; }
    }
}
