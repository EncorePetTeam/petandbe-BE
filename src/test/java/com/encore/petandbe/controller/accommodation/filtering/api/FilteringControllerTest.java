package com.encore.petandbe.controller.accommodation.filtering.api;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static com.epages.restdocs.apispec.MockMvcRestDocumentationWrapper.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.restdocs.request.RequestDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.encore.petandbe.controller.accommodation.filtering.requests.FilteringAccommodationRequests;
import com.encore.petandbe.controller.accommodation.filtering.responses.FilteringAccommodationListResponse;
import com.encore.petandbe.controller.accommodation.filtering.responses.FilteringAccommodationResponse;
import com.encore.petandbe.service.accommodation.filtering.FilteringService;

@WebMvcTest(controllers = FilteringController.class)
@AutoConfigureRestDocs
class FilteringControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private FilteringService filteringService;

	@Test
	@DisplayName("Filtering Accommodation - success")
	void filteringAccommodationSuccess() throws Exception {
		//given
		Long accommodationId = 1L;
		String responseAccommodationName = "정정일 애견호텔 & 유치원";
		String responseAddress = "서울특별시 중구 동호로 249";
		double avgRate = 4.8;

		MultiValueMap<String, String> info = new LinkedMultiValueMap<>();
		info.add("address", "서울특별시 중구");
		info.add("checkIn", "2022-11-15 16:00:00");
		info.add("checkOut", "2022-11-18 11:00:00");
		info.add("petCategory", "Dog");
		info.add("weight", "4.9");
		info.add("sortCategory", "평점순");
		info.add("page", "3");

		List<FilteringAccommodationResponse> filteringAccommodationResponses = new ArrayList<>();

		for (int i = 0; i < 10; i++) {
			Long id = accommodationId + i;
			String accommodationName = responseAccommodationName + i;
			String address = responseAddress + i;
			double rate = avgRate - (i / 10);

			FilteringAccommodationResponse filteringAccommodationResponse = new FilteringAccommodationResponse(id,
				accommodationName, address, rate);
			filteringAccommodationResponses.add(filteringAccommodationResponse);
		}

		FilteringAccommodationListResponse filteringAccommodationListResponse = new FilteringAccommodationListResponse(
			filteringAccommodationResponses);

		when(filteringService.filteringAccommodation(any(FilteringAccommodationRequests.class))).thenReturn(
			filteringAccommodationListResponse);
		//when
		ResultActions resultActions = mockMvc.perform(RestDocumentationRequestBuilders
			.get("/filtering/accommodation")
			.params(info)
			.accept(MediaType.APPLICATION_JSON));
		//then
		resultActions.andExpect(status().isOk())
			.andDo(document("filtering-accommodation",
				requestParameters(
					parameterWithName("address").description("주소"),
					parameterWithName("checkIn").description("체크인 시간 날짜"),
					parameterWithName("checkOut").description("체크아웃 시간 날짜"),
					parameterWithName("petCategory").description("반려동물종"),
					parameterWithName("weight").description("반려동물 무게"),
					parameterWithName("sortCategory").description("정렬방법"),
					parameterWithName("page").description("페이지 번호")
				),
				responseFields(
					fieldWithPath("filteringAccommodationList").type(JsonFieldType.ARRAY).description("필터 결과 List"),
					fieldWithPath("filteringAccommodationList[].accommodationId").type(JsonFieldType.NUMBER)
						.description("숙소 Id"),
					fieldWithPath("filteringAccommodationList[].accommodationName").type(JsonFieldType.STRING)
						.description("숙소 이름"),
					fieldWithPath("filteringAccommodationList[].address").type(JsonFieldType.STRING)
						.description("숙소 주소"),
					fieldWithPath("filteringAccommodationList[].avgRate").type(JsonFieldType.NUMBER)
						.description("숙소 평점")
				)
			)).andDo(print());
	}

	@Test
	@DisplayName("No Filtering Accommodation - success")
	void noFilteringAccommodationSuccess() throws Exception {
		//given
		Long accommodationId = 1L;
		String responseAccommodationName = "정정일 애견호텔 & 유치원";
		String responseAddress = "서울특별시 중구 동호로 249";
		double avgRate = 4.8;

		List<FilteringAccommodationResponse> filteringAccommodationResponses = new ArrayList<>();

		for (int i = 0; i < 10; i++) {
			Long id = accommodationId + i;
			String accommodationName = responseAccommodationName + i;
			String address = responseAddress + i;
			double rate = avgRate - (i / 10);

			FilteringAccommodationResponse filteringAccommodationResponse = new FilteringAccommodationResponse(id,
				accommodationName, address, rate);
			filteringAccommodationResponses.add(filteringAccommodationResponse);
		}

		FilteringAccommodationListResponse filteringAccommodationListResponse = new FilteringAccommodationListResponse(
			filteringAccommodationResponses);

		when(filteringService.filteringAccommodation(any(FilteringAccommodationRequests.class))).thenReturn(
			filteringAccommodationListResponse);
		//when
		ResultActions resultActions = mockMvc.perform(RestDocumentationRequestBuilders
			.get("/filtering/accommodation")
			.accept(MediaType.APPLICATION_JSON));
		//then
		resultActions.andExpect(status().isOk())
			.andDo(document("no-filtering-accommodation",
				responseFields(
					fieldWithPath("filteringAccommodationList").type(JsonFieldType.ARRAY).description("필터 결과 List"),
					fieldWithPath("filteringAccommodationList[].accommodationId").type(JsonFieldType.NUMBER)
						.description("숙소 Id"),
					fieldWithPath("filteringAccommodationList[].accommodationName").type(JsonFieldType.STRING)
						.description("숙소 이름"),
					fieldWithPath("filteringAccommodationList[].address").type(JsonFieldType.STRING)
						.description("숙소 주소"),
					fieldWithPath("filteringAccommodationList[].avgRate").type(JsonFieldType.NUMBER)
						.description("숙소 평점")
				)
			)).andDo(print());
	}
}