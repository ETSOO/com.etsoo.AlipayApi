namespace com.etsoo.AliAmapApi.RQ
{
    /// <summary>
    /// Amap request
    /// 高德地图请求
    /// </summary>
    internal record AmapRequest : AmapRequestBase
    {
        public AmapRequest(SearchPlaceRQ rq, string key, string? privateKey) : base(rq, key, privateKey)
        {
            if (!string.IsNullOrEmpty(rq.Region))
            {
                Parameters["region"] = rq.Region;
            }

            if (rq.Types != null)
            {
                Parameters["types"] = string.Join('|', rq.Types);
            }

            if (rq.ShowFields != null)
            {
                Parameters["show_fields"] = string.Join(',', rq.ShowFields);
            }

            if (rq.PageSize.HasValue) Parameters["page_size"] = rq.PageSize.Value.ToString();
            if (rq.PageNum.HasValue) Parameters["page_num"] = rq.PageNum.Value.ToString();

            var polygon = rq.Polygon;
            if (polygon is not null)
            {
                if (polygon.Count() > 2)
                {
                    // 多边形为矩形时，可传入左上右下两顶点坐标对
                    // 首尾坐标对需相同
                    var first = polygon.First();
                    var last = polygon.Last();
                    if (first.Lat != last.Lat || first.Lng != last.Lng)
                    {
                        var firstRepeat = first with { };
                        polygon = polygon.Append(firstRepeat);
                    }
                }

                Parameters["polygon"] = string.Join("|", polygon.Select(b => b.ToLngLatString()));
            }
        }

        protected override void AddOutput(AmapBaseRQ rq)
        {
            Parameters["output"] = rq.Output.ToString().ToLower();
        }
    }
}
