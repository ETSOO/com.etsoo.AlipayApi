namespace com.etsoo.AliAmapApi.RQ
{
    /// <summary>
    /// Amap autocomplete request
    /// 高德地图自动填充请求
    /// </summary>
    internal record AmapAutocompleteRequest : AmapRequestBase
    {
        public AmapAutocompleteRequest(AutocompleteRQ rq, string key, string? privateKey) : base(rq, key, privateKey)
        {
            if (rq.Type != null)
            {
                Parameters["type"] = string.Join('|', rq.Type);
            }

            if (!string.IsNullOrEmpty(rq.City))
            {
                Parameters["city"] = rq.City;
            }
        }
    }
}
