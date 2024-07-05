using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace com.etsoo.AlipayApi
{
    /// <summary>
    /// Alipay API service collection extensions
    /// 支付宝API服务集合扩展
    /// </summary>
    public static class AlipayApiServiceCollectionExtensions
    {
        /// <summary>
        /// Add Alipay client
        /// 添加支付宝客户端
        /// </summary>
        /// <param name="services">Services</param>
        /// <param name="configuration">configuration</param>
        /// <returns>Services</returns>
        public static IServiceCollection AddAlipayClient(this IServiceCollection services, IConfigurationSection configuration)
        {
            services.AddSingleton<IValidateOptions<AlipayClientOptions>, ValidateAlipayClientOptions>();
            services.AddOptions<AlipayClientOptions>().Bind(configuration).ValidateOnStart();
            services.AddHttpClient<IAlipayClient, AlipayClient>();
            return services;
        }
    }
}
