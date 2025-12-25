using com.etsoo.ApiModel.Dto.Maps;

namespace com.etsoo.AliAmapApi.Dto
{
    /// <summary>
    /// Amap place tip
    /// 高德地图地点提示
    /// </summary>
    public record AmapPlaceTip
    {
        /// <summary>
        /// 若数据为 POI 类型，则返回 POI ID;若数据为 bus 类型，则返回 bus id;若数据为 busline 类型，则返回 busline id
        /// </summary>
        public required string Id { get; init; }

        /// <summary>
        /// tip 名称
        /// </summary>
        public required string Name { get; init; }

        /// <summary>
        /// 所属区域，省+市+区（直辖市为“市+区”）
        /// </summary>
        public required string District { get; init; }

        /// <summary>
        /// 六位区县编码
        /// </summary>
        public required string Adcode {  get; init; }

        /// <summary>
        /// tip 中心点坐标
        /// </summary>
        public string? Location { get; init; }

        /// <summary>
        /// Location object
        /// 位置对象
        /// </summary>
        public Location? LocationObj
        {
            get
            {
                var parts = Location?.Split(',');
                if (parts != null && parts.Length == 2 && float.TryParse(parts[0], out var lng) && float.TryParse(parts[1], out var lat))
                {
                    return new Location(lat, lng);
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// 详细地址
        /// </summary>
        public required string Address { get; init; }
    }
}
