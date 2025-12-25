using com.etsoo.ApiModel.Dto.Maps;
using com.etsoo.ApiModel.RQ.Maps;

namespace com.etsoo.AliAmapApi.RQ
{
    /// <summary>
    /// Search place request data
    /// https://lbs.amap.com/api/webservice/guide/api-advanced/newpoisearch
    /// 查询地点请求数据
    /// </summary>
    public record SearchPlaceRQ : AmapBaseRQ
    {
        /// <summary>
        /// Create from common query request data
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <returns>Result</returns>
        public static SearchPlaceRQ CreateFrom(PlaceQueryRQ rq)
        {
            return new SearchPlaceRQ
            {
                Keywords = rq.Query,
                Region = rq.Region,
                PageSize = rq.PageSize
            };
        }

        /// <summary>
        /// Region to search, default China
        /// 搜索区划，默认中国
        /// </summary>
        public string? Region { get; init; }

        /// <summary>
        /// Place types
        /// 指定地点类型
        /// </summary>
        public IEnumerable<string>? Types { get; init; }

        /// <summary>
        /// Specify more fields information in the return result
        /// 指定返回结果的更多字段信息
        /// </summary>
        public IEnumerable<string>? ShowFields { get; init; }

        /// <summary>
        /// Page size
        /// 单次请求POI数量
        /// </summary>
        public int? PageSize { get; init; }

        /// <summary>
        /// Page number
        /// 分页页码，默认为0，0代表第一页
        /// </summary>
        public int? PageNum { get; init; }

        /// <summary>
        /// Circle area radius, in meters, default is 1000
        /// 圆形区域检索半径，单位为米
        /// </summary>
        public int? Radius { get; init; }

        /// <summary>
        /// The area of the polygon
        /// 检索多边形区域。需传入多个坐标对集合，坐标对用"|"分割。多边形为矩形时，可传入左上右下两顶点坐标对
        /// </summary>
        public IEnumerable<Location>? Polygon { get; init; }
    }
}
