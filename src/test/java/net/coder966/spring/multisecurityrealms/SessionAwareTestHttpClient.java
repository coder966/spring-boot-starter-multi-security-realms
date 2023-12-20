package net.coder966.spring.multisecurityrealms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class SessionAwareTestHttpClient {

    final int port;
    final TestRestTemplate testRestTemplate = new TestRestTemplate();
    final List<String> cookies = new ArrayList<>();


    public SessionAwareTestHttpClient(int port) {
        this.port = port;
    }

    public Request request(HttpMethod method, String uri) {
        return new Request(this, method, uri);
    }

    public static class Request {

        private final SessionAwareTestHttpClient client;
        private final String uri;
        private final HttpMethod method;
        private final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();

        Request(SessionAwareTestHttpClient client, HttpMethod method, String uri) {
            this.client = client;
            this.method = method;
            this.uri = uri;
        }

        public ResponseSpec exchange() {
            LinkedMultiValueMap<String, String> mergedHeaders = new LinkedMultiValueMap<>();
            mergedHeaders.addAll(headers);
            client.cookies.forEach(header -> {
                mergedHeaders.add("Cookie", header);
            });

            ResponseEntity<Object> response = client.testRestTemplate.exchange(
                "http://localhost:" + client.port + uri,
                method,
                new HttpEntity<>(mergedHeaders),
                Object.class
            );

            List<String> cookiesHeader = response.getHeaders().get("Set-Cookie");
            if(cookiesHeader != null){
                client.cookies.addAll(cookiesHeader);
            }

            return new ResponseSpec(response);
        }

        public Request header(String key, String value) {
            headers.add(key, value);
            return this;
        }
    }

    public static class ResponseSpec {

        private final ResponseEntity<Object> response;

        ResponseSpec(ResponseEntity<Object> response) {
            this.response = response;
        }

        public ResponseSpec expectStatus(int code) {
            assertEquals(code, response.getStatusCode().value());
            return this;
        }

        public ResponseSpec expectHeaderExists(String headerName) {
            assertNotNull(response.getHeaders().get(headerName));
            return this;
        }

        public ResponseSpec expectHeaderDoesNotExist(String headerName) {
            assertNull(response.getHeaders().get(headerName));
            return this;
        }

        public ResponseSpec expectHeader(String headerName, String headerValue) {
            assertEquals(headerValue, response.getHeaders().get(headerName).getFirst());
            return this;
        }
    }
}
