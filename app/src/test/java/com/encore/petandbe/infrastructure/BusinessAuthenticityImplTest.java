package com.encore.petandbe.infrastructure;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.encore.petandbe.controller.user.host.requests.HostRegistrationRequest;

@SpringBootTest
class BusinessAuthenticityImplTest {

	@Autowired
	private BusinessAuthenticity businessAuthenticity;

	@Test
	@DisplayName("check authenticity - success")
	void checkAuthenticitySuccess() throws IOException {

		String hostName = "신연주";
		String registrationNumber = "8048800448";
		String openDate = "20160519";

		HostRegistrationRequest hostRegistrationRequest = new HostRegistrationRequest(registrationNumber, hostName,
			openDate);

		boolean result = businessAuthenticity.checkAuthenticity(hostRegistrationRequest);

		assertEquals(true, result);
	}

	@Test
	@DisplayName("check authenticity - fail")
	void checkAuthenticityFail() throws IOException {

		String hostName = "정정일";
		String registrationNumber = "1111111111";
		String openDate = "19980428";

		HostRegistrationRequest hostRegistrationRequest = new HostRegistrationRequest(registrationNumber, hostName,
			openDate);

		boolean result = businessAuthenticity.checkAuthenticity(hostRegistrationRequest);

		assertEquals(false, result);
	}
}