using System.Text.Json.Serialization;

namespace com.etsoo.AlipayApi
{
    /// <summary>
    /// JSON serializer context
    /// JSON 序列化器上下文
    /// </summary>
    [JsonSourceGenerationOptions(
        PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    )]
    [JsonSerializable(typeof(Auth.AlipayTokenData))]
    [JsonSerializable(typeof(Auth.AlipayUserInfo))]
    public partial class AlipayJsonSerializerContext : JsonSerializerContext
    {
    }
}
