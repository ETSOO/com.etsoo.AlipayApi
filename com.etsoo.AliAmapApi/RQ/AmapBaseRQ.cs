using com.etsoo.ApiModel.Dto.Maps;
using com.etsoo.ApiModel.RQ.Maps;

namespace com.etsoo.AliAmapApi.RQ
{
    /// <summary>
    /// Amap base request data
    /// 高德地图基础请求数据
    /// </summary>
    public record AmapBaseRQ
    {
        /// <summary>
        /// Output format
        /// 输出格式
        /// </summary>
        public ApiOutput Output { get; init; } = ApiOutput.JSON;

        /// <summary>
        /// Place keywords
        /// 需要被检索的地点文本信息
        /// </summary>
        public required string Keywords { get; init; }

        /// <summary>
        /// Center location
        /// 中心地点
        /// </summary>
        public Location? Location { get; init; }

        /// <summary>
        /// 取值为"true"，仅返回region中指定城市检索结果
        /// </summary>
        public bool? CityLimit { get; init; }
    }
}
