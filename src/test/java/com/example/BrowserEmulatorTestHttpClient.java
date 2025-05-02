package com.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Slf4j
public class BrowserEmulatorTestHttpClient {

    final String clientId;
    final int port;
    final TestRestTemplate testRestTemplate = new TestRestTemplate();
    final List<String> cookies = new ArrayList<>();


    public BrowserEmulatorTestHttpClient(int port, String clientId) {
        this.port = port;
        this.clientId = clientId;

        // simulate visiting the homepage
        // essential to obtain the CSRF token
        request(HttpMethod.GET, "/").exchange();
    }

    public Request request(HttpMethod method, String uri) {
        return new Request(this, method, uri);
    }

    public static class Request {

        private final BrowserEmulatorTestHttpClient client;
        private final String uri;
        private final HttpMethod method;
        private final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        private Object body;

        Request(BrowserEmulatorTestHttpClient client, HttpMethod method, String uri) {
            this.client = client;
            this.method = method;
            this.uri = uri;
        }

        public ResponseSpec<Object> exchange() {
            return exchange(Object.class);
        }

        public <T> ResponseSpec<T> exchange(@Nullable Class<T> clazz) {
            LinkedMultiValueMap<String, String> mergedHeaders = new LinkedMultiValueMap<>();
            mergedHeaders.addAll(headers);
            mergedHeaders.add("X-Client-Id", client.clientId);

            client.cookies.forEach(header -> {
                mergedHeaders.add("Cookie", header);

                if(header.startsWith("XSRF-TOKEN=")){
                    mergedHeaders.add("X-XSRF-TOKEN", header.replace("XSRF-TOKEN=", "").replace("; Path=/", ""));
                }
            });


            ResponseEntity<T> response = client.testRestTemplate.exchange(
                "http://localhost:" + client.port + uri,
                method,
                new HttpEntity<>(body, mergedHeaders),
                clazz
            );

            List<String> cookiesHeader = response.getHeaders().get("Set-Cookie");
            if(cookiesHeader != null){
                log.info("Client {} Received Cookies: {}", client.clientId, cookiesHeader);
                client.cookies.addAll(cookiesHeader);
            }

            return new ResponseSpec<>(response);
        }

        public Request header(String key, String value) {
            headers.add(key, value);
            return this;
        }

        public Request body(Object body) {
            this.body = body;
            return this;
        }
    }

    public static class ResponseSpec<T> {

        private final ResponseEntity<T> response;

        ResponseSpec(ResponseEntity<T> response) {
            this.response = response;
        }

        public ResponseSpec<T> expectStatus(int code) {
            assertEquals(code, response.getStatusCode().value());
            return this;
        }

        public ResponseSpec<T> expectHeaderExists(String headerName) {
            assertNotNull(response.getHeaders().get(headerName));
            return this;
        }

        public ResponseSpec<T> expectHeaderDoesNotExist(String headerName) {
            assertNull(response.getHeaders().get(headerName));
            return this;
        }

        public ResponseSpec<T> expectHeader(String headerName, String headerValue) {
            assertEquals(headerValue, response.getHeaders().get(headerName).get(0));
            return this;
        }

        public ResponseSpec<T> expectBody(T expected) {
            assertEquals(expected, response.getBody());
            return this;
        }

        public ResponseSpec<T> expectBodyNotEqual(T unexpected) {
            assertNotEquals(unexpected, response.getBody());
            return this;
        }

        public T readBody() {
            return response.getBody();
        }
    }
}
