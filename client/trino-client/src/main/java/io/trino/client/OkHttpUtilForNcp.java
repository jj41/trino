/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.client;

import okhttp3.Interceptor;
import okhttp3.Response;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

public final class OkHttpUtilForNcp
{
    private OkHttpUtilForNcp() {}

    public static Interceptor iamAuth(String accessKey, String secretKey)
    {
        return IamAuthInterceptor.newIamAuthInterceptor(accessKey, secretKey);
    }

    static final class IamAuthInterceptor
            implements Interceptor
    {
        private static IamAuthInterceptor instance;
        private final String accessKey;
        private final String secretKey;

        private IamAuthInterceptor(String accessKey, String secretKey)
        {
            this.accessKey = accessKey;
            this.secretKey = secretKey;
        }

        public static IamAuthInterceptor newIamAuthInterceptor(String accessKey, String secretKey)
        {
            if (instance == null) {
                instance = new IamAuthInterceptor(accessKey, secretKey);
            }
            return instance;
        }

        @Override
        public Response intercept(Chain chain)
                throws IOException
        {
            requireNonNull(accessKey, "accessKey is null");
            requireNonNull(secretKey, "secretKey is null");

            try {
                final String xNcpApigwTimestamp = "x-ncp-apigw-timestamp";
                final String xNcpIamAccessKey = "x-ncp-iam-access-key";
                final String xNcpApigwSignatureV2 = "x-ncp-apigw-signature-v2";

                String timestamp = String.valueOf(System.currentTimeMillis());
                String signature = makeSignature(accessKey, secretKey, timestamp);
                return chain.proceed(chain.request().newBuilder()
                        .header(xNcpApigwTimestamp, timestamp)
                        .header(xNcpIamAccessKey, accessKey)
                        .header(xNcpApigwSignatureV2, signature)
                        .build());
            }
            catch (Exception e) {
                throw new ClientException("Error setting up signature header: " + e.getMessage(), e);
            }
        }

        private static String makeSignature(String accessKey, String secretKey, String timestamp)
                throws NoSuchAlgorithmException, InvalidKeyException
        {
            String space = " ";
            String newLine = "\n";
            String method = "POST";  // GET | POST | ...
            String url = "/query/kr/v1/statement";  // /query/kr/v1/statement

            String message = new StringBuilder()
                    .append(method)
                    .append(space)
                    .append(url)
                    .append(newLine)
                    .append(timestamp)
                    .append(newLine)
                    .append(accessKey)
                    .toString();

            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return new String(Base64.getEncoder().encode(rawHmac), StandardCharsets.UTF_8);
        }
    }
}
