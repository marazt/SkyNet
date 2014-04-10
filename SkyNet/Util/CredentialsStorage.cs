using System.IO;
using RestSharp;
using RestSharp.Deserializers;
using RestSharp.Serializers;
using SkyNet.Model;

namespace SkyNet.Util
{
    /// <summary>
    /// Helper class for (de)serialization of the user token       
    /// </summary>
    public static class CredentialsStorage
    {

        #region Constrants

        private const string StorageFile = "user_token.json";

        #endregion Constrants



        #region Methods

        /// <summary>
        /// Saves the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        public static void Save(UserToken token)
        {
            using (var stream = new StreamWriter(StorageFile))
            {
                var serializer = new JsonSerializer();
                stream.Write(serializer.Serialize(token));
            }
        }

        /// <summary>
        /// Loads this instance.
        /// </summary>
        /// <returns>UserToken instance if storage file exists, otherwise null</returns>
        public static UserToken Load()
        {
            if (!System.IO.File.Exists(StorageFile))
            {
                return null;
            }

            using (var stream = new StreamReader(StorageFile))
            {
                var deserializer = new JsonDeserializer();
                return deserializer.Deserialize<UserToken>(new RestResponse { Content = stream.ReadToEnd() });

            }
        }

        #endregion Methods

    }

}
