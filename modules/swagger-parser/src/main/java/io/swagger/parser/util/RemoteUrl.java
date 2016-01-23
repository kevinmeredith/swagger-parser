package io.swagger.parser.util;

import io.swagger.models.auth.AuthorizationValue;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public class RemoteUrl {

    private static final String ACCEPT_HEADER_VALUE = "application/json, application/yaml, */*";
    private static CloseableHttpClient httpClient;

    private static synchronized CloseableHttpClient getCarelessHttpClient() {

        if (httpClient == null) {
            try {
                SSLContextBuilder builder = new SSLContextBuilder();
                builder.loadTrustMaterial(null, new TrustStrategy() {
                    public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        return true;
                    }
                });
                SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(), NoopHostnameVerifier.INSTANCE);
                httpClient = HttpClients
                    .custom()
                    .setSSLSocketFactory(sslsf)
                    .build();
            } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
                System.err.println("can't disable SSL verification;" + e);
            }
        }

        return httpClient;
    }

    public static String urlToString(String url, List<AuthorizationValue> auths) throws Exception {

        HttpGet getMethod = new HttpGet(url);
        getMethod.setHeader("Accept", ACCEPT_HEADER_VALUE);

        if (auths != null) {
            StringBuilder queryString = new StringBuilder();
            // build a new url if needed
            for (AuthorizationValue auth : auths) {
                if ("query".equals(auth.getType())) {
                    if (queryString.toString().length() == 0) {
                        queryString.append("?");
                    } else {
                        queryString.append("&");
                    }
                    queryString.append(URLEncoder.encode(auth.getKeyName(), "UTF-8"))
                        .append("=")
                        .append(URLEncoder.encode(auth.getValue(), "UTF-8"));
                }
            }
            if (queryString.toString().length() != 0) {
                url = url + queryString.toString();
            }

            getMethod.setURI(URI.create(url));
            for (AuthorizationValue auth : auths) {
                if ("header".equals(auth.getType())) {
                    getMethod.setHeader(auth.getKeyName(), auth.getValue());
                }
            }
        }

        final CloseableHttpClient httpClient = getCarelessHttpClient();

        if (httpClient != null) {
            final CloseableHttpResponse response = httpClient.execute(getMethod);

            try {
                HttpEntity entity = response.getEntity();
                return EntityUtils.toString(entity, "UTF-8");
            } finally {
                response.close();
            }
        } else {
            throw new IOException("CloseableHttpClient could not be initialized");
        }
    }
}
