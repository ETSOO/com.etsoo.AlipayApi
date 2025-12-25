using com.etsoo.ApiModel.Dto.Maps;
using System.Text;

namespace com.etsoo.AliAmapApi.Dto
{
    /// <summary>
    /// Amap place (poi)
    /// 高德地图地址
    /// </summary>
    public record AmapPlace
    {
        /// <summary>
        /// 唯一标识
        /// </summary>
        public required string Id { get; init; }

        /// <summary>
        /// 名称
        /// </summary>
        public required string Name { get; init; }

        /// <summary>
        /// 所属类型
        /// </summary>
        public string? Type { get; init; }

        /// <summary>
        /// 经纬度
        /// </summary>
        public required string Location { get; init; }

        /// <summary>
        /// Location object
        /// 位置对象
        /// </summary>
        public Location LocationObj
        {
            get
            {
                var parts = Location.Split(',');
                if (parts.Length == 2 && float.TryParse(parts[0], out var lng) && float.TryParse(parts[1], out var lat))
                {
                    return new Location(lat, lng);
                }
                else
                {
                    return new Location(0, 0);
                }
            }
        }

        /// <summary>
        /// 所属省份
        /// </summary>
        public required string Pname { get; init; }

        /// <summary>
        /// 所属城市
        /// </summary>
        public required string Cityname { get; init; }

        /// <summary>
        /// 所属区县
        /// </summary>
        public required string Adname { get; init; }

        /// <summary>
        /// 所属区域编码
        /// </summary>
        public required string Adcode {  get; init; }

        /// <summary>
        /// 所属城市编码
        /// </summary>
        public required string Citycode { get; init; }

        /// <summary>
        /// 详细地址
        /// </summary>
        public required string Address { get; init; }

        /// <summary>
        /// Create common place
        /// 创建通用地点
        /// </summary>
        /// <param name="query">Original query</param>
        /// <returns>Result</returns>
        public PlaceCommon CreateCommon(string query)
        {
            var fa = new StringBuilder(Pname);

            if (Cityname != Pname)
            {
                fa.Append(Cityname);
            }

            fa.Append(Adname);
            fa.Append(Address);

            return new PlaceCommon
            {
                PlaceId = Id,
                Name = Name,
                Location = LocationObj,
                FormattedAddress = fa.ToString(),
                Region = "CN",
                State = Pname,
                City = Cityname,
                District = Adname
            };
        }
    }
}
