package com.example;

import com.example.dto.AuthOtpStepRequest;
import com.example.dto.AuthUsernameAndPasswordStepRequest;
import com.example.other.Constants;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;

@Slf4j
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class MultiSecurityRealmTest {

    @LocalServerPort
    private int port;

    @Test
    public void testLoginWithUserFromDifferentRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testLoginWithUserFromDifferentRealm");

        client
            .request(HttpMethod.POST, "/normal-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(ErrorResponse.class)
            .expectStatus(400)
            .expectBody(new ErrorResponse(Constants.ErrorCodes.BAD_CREDENTIALS));

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("mohammed", "mpass"))
            .exchange(ErrorResponse.class)
            .expectStatus(400)
            .expectBody(new ErrorResponse(Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testAuthenticationFailure() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAuthenticationFailure");

        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("0000"))
            .exchange(ErrorResponse.class)
            .expectStatus(400)
            .expectBody(new ErrorResponse(Constants.ErrorCodes.BAD_OTP));
    }

    @Test
    public void testAuthenticationSuccess() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAuthenticationSuccess");

        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null));
    }

    @Test
    public void testTokenTtl() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAuthenticationSuccess");

        SuccessResponse loginResponse1 = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, Duration.ofMinutes(5).toSeconds()))
            .readBody();

        SuccessResponse loginResponse2 = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse1.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, Duration.ofHours(8).toSeconds()))
            .readBody();
    }

    @Test
    public void testAccessingProtectedApiFromAnotherRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAccessingProtectedApiFromAnotherRealm");

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(null)
            .expectStatus(403);

        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("khalid");

        client
            .request(HttpMethod.GET, "/normal-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(null)
            .expectStatus(403);
    }

    @Test
    public void testAccessingPublicApis() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAccessingPublicApis");

        client
            .request(HttpMethod.GET, "/my-first-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("my-first-open-api");

        // with a request mapping on controller class, which is different to the above case
        client
            .request(HttpMethod.GET, "/open-apis/my-second-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("my-second-open-api");

        // no path in method level, only controller (try with no trailing slash)
        client
            .request(HttpMethod.GET, "/open-apis")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("my-second-open-api-v2");

        // with a request mapping on controller class which has a @PreAuthorize, which is different to the above case
        client
            .request(HttpMethod.GET, "/open-apis-3/my-third-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("my-third-open-api");
    }

    @Test
    public void testAccessingProtectedApisWithAuthenticationNotFinishedAllSteps() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAccessingProtectedApisWithAuthenticationNotFinishedAllSteps");

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(SuccessResponse.class)
            .expectStatus(403);

        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(SuccessResponse.class)
            .expectStatus(403);

        client
            .request(HttpMethod.GET, "/admin-user/no-pre-authorize")
            .header("Authorization", loginResponse.getToken())
            .exchange()
            .expectStatus(403);

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("khalid");

        client
            .request(HttpMethod.GET, "/admin-user/no-pre-authorize")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200);
    }

    @Test
    public void testTransactionalSupport() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testTransactionalSupport");

        // Login to read the current counter

        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();

        int loginCounter = client
            .request(HttpMethod.GET, "/admin-user/my-login-counter")
            .header("Authorization", loginResponse.getToken())
            .exchange(Integer.class)
            .expectStatus(200)
            .readBody();

        // now attempt a failed login, and then read the counter

        SuccessResponse login2Response = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", login2Response.getToken())
            .body(new AuthOtpStepRequest("0000"))
            .exchange(ErrorResponse.class)
            .expectStatus(400)
            .expectBody(new ErrorResponse(Constants.ErrorCodes.BAD_OTP))
            .readBody();

        login2Response = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", login2Response.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-login-counter")
            .header("Authorization", login2Response.getToken())
            .exchange(Integer.class)
            .expectStatus(200)
            .expectBody(loginCounter + 1)
            .readBody();
    }

    @Test
    public void loginAgainAfterCompleteSuccessfulLogin() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "loginAgainAfterCompleteSuccessfulLogin");

        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();

        // already logged in, idempotent operation
        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();
    }

    @Test
    public void authenticatedUserCanAccessPublicApi() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "authenticatedUserCanAccessPublicApi");

        // partially authenticated
        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null, null))
            .readBody();

        // public api
        client
            .request(HttpMethod.GET, "/my-first-open-api")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("my-first-open-api");

        // fully authenticated
        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, null, null))
            .readBody();

        // public api
        client
            .request(HttpMethod.GET, "/my-first-open-api")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("my-first-open-api");
    }

    @Test
    public void canAccessActuators() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "canAccessActuators");

        String healthResponse = client
            .request(HttpMethod.GET, "/actuator/health")
            .exchange(String.class)
            .expectStatus(200)
            .readBody();

        System.out.println(healthResponse);
    }

    @Test
    public void extrasPresentInResponse() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "extrasPresentInResponse");

        // partially authenticated
        SuccessResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, Collections.emptyMap(), null))
            .readBody();

        // fully authenticated
        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(SuccessResponse.class)
            .expectStatus(200)
            .expectBody(new SuccessResponse("ADMIN_USER", "ANY", null, Map.of("countBadges", 0), null))
            .readBody();
    }

    @Setter
    @Getter
    @ToString
    @AllArgsConstructor
    public static class SuccessResponse {
        private String realm;
        private String token;
        private String nextAuthenticationStep;
        private Map<String, Object> extras;
        private Long expiresInSeconds;

        @Override
        public boolean equals(Object other) {
            if(!(other instanceof SuccessResponse otherResponse)){
                return false;
            }

            return Objects.equals(realm, otherResponse.getRealm()) &&
                Objects.equals(nextAuthenticationStep, otherResponse.getNextAuthenticationStep()) &&
                (token == null ? otherResponse.getToken() == null : (token.equals("ANY") || Objects.equals(token, otherResponse.getToken()))) &&
                (extras == null || Objects.equals(extras, otherResponse.getExtras())) &&
                (expiresInSeconds == null || Objects.equals(expiresInSeconds, otherResponse.getExpiresInSeconds()));
        }
    }

    @Setter
    @Getter
    @ToString
    @AllArgsConstructor
    public static class ErrorResponse {
        private String error;

        @Override
        public boolean equals(Object other) {
            if(!(other instanceof ErrorResponse otherResponse)){
                return false;
            }

            return Objects.equals(error, otherResponse.getError());
        }
    }

}