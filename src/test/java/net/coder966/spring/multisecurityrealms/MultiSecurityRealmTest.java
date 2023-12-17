package net.coder966.spring.multisecurityrealms;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import net.coder966.spring.multisecurityrealms.other.Constants;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@AutoConfigureMockMvc
@SpringBootTest
public class MultiSecurityRealmTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void testUserFromRealm2InRealm1() throws Exception {
        mvc.perform(
                post("/normal-user/login")
                    .header(Constants.Headers.USERNAME, "khalid")
                    .header(Constants.Headers.PASSWORD, "kpass")
            )
            .andExpect(status().is(401))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().stringValues(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testUserFromRealm1InRealm2() throws Exception {
        mvc.perform(
                post("/admin-user/login")
                    .header(Constants.Headers.USERNAME, "mohammed")
                    .header(Constants.Headers.PASSWORD, "mpass")
            )
            .andExpect(status().is(401))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().stringValues(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    // -------------------------------------------------------------------------------------------------------------------------------------

    @Test
    public void testRealm1FirstStepFailure() throws Exception {
        mvc.perform(
                post("/normal-user/login")
                    .header(Constants.Headers.USERNAME, "tester")
                    .header(Constants.Headers.PASSWORD, "wrong")
            )
            .andExpect(status().is(401))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().stringValues(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testRealm1FirstStepSuccess() throws Exception {
        mvc.perform(
                post("/normal-user/login")
                    .header(Constants.Headers.USERNAME, "mohammed")
                    .header(Constants.Headers.PASSWORD, "mpass")
            )
            .andExpect(status().is(200))
            .andExpect(header().stringValues(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME));
    }

    @Test
    public void testRealm1SecondStepFailure() throws Exception {
        testRealm1FirstStepSuccess();
        mvc.perform(
                post("/normal-user/login")
                    .header(Constants.Headers.OTP, "0000")
            )
            .andExpect(status().is(401))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().stringValues(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_OTP));
    }

    @Test
    public void testRealm1SecondStepSuccess() throws Exception {
        testRealm1FirstStepSuccess();
        mvc.perform(
                post("/normal-user/login")
                    .header(Constants.Headers.OTP, "1234")
            )
            .andExpect(status().is(200))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME));
    }

    @Test
    public void testRealm1Logout() throws Exception {
        mvc.perform(post("/normal-user/logout"))
            .andExpect(status().is(200));
    }

    // -------------------------------------------------------------------------------------------------------------------------------------

    @Test
    public void testRealm2FirstStepFailure() throws Exception {
        mvc.perform(
                post("/admin-user/login")
                    .header(Constants.Headers.USERNAME, "tester")
                    .header(Constants.Headers.PASSWORD, "wrong")
            )
            .andExpect(status().is(401))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().stringValues(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testRealm2FirstStepSuccess() throws Exception {
        mvc.perform(
                post("/admin-user/login")
                    .header(Constants.Headers.USERNAME, "khalid")
                    .header(Constants.Headers.PASSWORD, "kpass")
            )
            .andExpect(status().is(200))
            .andExpect(header().stringValues(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME));
    }

    @Test
    public void testRealm2SecondStepFailure() throws Exception {
        testRealm2FirstStepSuccess();
        mvc.perform(
                post("/admin-user/login")
                    .header(Constants.Headers.OTP, "0000")
            )
            .andExpect(status().is(401))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().stringValues(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_OTP));
    }

    @Test
    public void testRealm2SecondStepSuccess() throws Exception {
//        testRealm2FirstStepSuccess();
        mvc.perform(
                post("/admin-user/login")
                    .header(Constants.Headers.OTP, "1234")
            )
            .andExpect(status().is(200))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.NEXT_STEP_RESPONSE_HEADER_NAME))
            .andExpect(header().doesNotExist(MultiRealmAuthFilter.ERROR_CODE_RESPONSE_HEADER_NAME));
    }

    @Test
    public void testRealm2Logout() throws Exception {
        mvc.perform(post("/admin-user/logout"))
            .andExpect(status().is(200));
    }
}