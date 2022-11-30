package com.encore.petandbe.controller.accommodation.reservation.api;

import static com.epages.restdocs.apispec.MockMvcRestDocumentationWrapper.*;
import static org.mockito.Mockito.*;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.restdocs.request.RequestDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.encore.petandbe.controller.accommodation.reservation.requests.DeleteReservationRequest;
import com.encore.petandbe.controller.accommodation.reservation.requests.ReservationRegistrationRequest;
import com.encore.petandbe.controller.accommodation.reservation.requests.ReservationUpdatingRequest;
import com.encore.petandbe.controller.accommodation.reservation.responses.DeleteReservationResponse;
import com.encore.petandbe.controller.accommodation.reservation.responses.ReservationDetailsResponse;
import com.encore.petandbe.controller.accommodation.reservation.responses.ReservationRetrieveResponse;
import com.encore.petandbe.model.accommodation.filtering.category.PetCategory;
import com.encore.petandbe.service.accommodation.reservation.ReservationService;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(controllers = ReservationController.class)
@AutoConfigureRestDocs
class ReservationControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ReservationService reservationService;

	@Autowired
	private ObjectMapper objectMapper;

	private final Long reservationId = 1L;
	private final Long userId = 2L;
	private final Long roomId = 3L;
	private final Long accommodationId = 4L;
	private final String checkInDate = "2022-11-27 13:00:00";
	private final String checkOutDate = "2022-11-28 16:00:00";
	private final PetCategory petCategory = PetCategory.DOG;
	private final String weight = "4.7";
	private final String accommodationName = "정정일 애견 호텔";
	private final String roomName = "스위트 스위트 슈퍼 스위트 룸";

	@Test
	@DisplayName("Register reservation - success")
	void registerReservation() throws Exception {
		//given
		ReservationRegistrationRequest reservationRegistrationRequest = new ReservationRegistrationRequest(userId,
			roomId, checkInDate, checkOutDate, petCategory, weight);

		ReservationDetailsResponse reservationDetailsResponse = new ReservationDetailsResponse(reservationId, userId,
			roomId, checkInDate, checkOutDate, petCategory, weight);

		when(reservationService.registerReservation(any(ReservationRegistrationRequest.class))).thenReturn(
			reservationDetailsResponse);
		//when
		ResultActions resultActions = mockMvc.perform(
			post("/reservation")
				.content(objectMapper.writeValueAsString(reservationRegistrationRequest))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON));
		//then
		resultActions.andExpect(status().isCreated())
			.andDo(document("reservation-register",
				requestFields(
					fieldWithPath("roomId").type(JsonFieldType.NUMBER).description("예약한 Room 아이디"),
					fieldWithPath("userId").type(JsonFieldType.NUMBER).description("숙박 시설을 예약한 유저 아이디"),
					fieldWithPath("checkInDate").type(JsonFieldType.STRING).description("체크인 날짜 및 시간"),
					fieldWithPath("checkOutDate").type(JsonFieldType.STRING).description("체크아웃 날짜 및 시간"),
					fieldWithPath("petCategory").type(JsonFieldType.STRING).description("동반할 반려동물 종"),
					fieldWithPath("weight").type(JsonFieldType.STRING).description("동반할 반려동물 무게")
				),
				responseFields(
					fieldWithPath("reservationId").type(JsonFieldType.NUMBER).description("생성된 예약 아이디(pk)"),
					fieldWithPath("roomId").type(JsonFieldType.NUMBER).description("예약한 Room 아이디"),
					fieldWithPath("userId").type(JsonFieldType.NUMBER).description("숙박 시설을 예약한 유저 아이디"),
					fieldWithPath("checkInDate").type(JsonFieldType.STRING).description("체크인 날짜 및 시간"),
					fieldWithPath("checkOutDate").type(JsonFieldType.STRING).description("체크아웃 날짜 및 시간"),
					fieldWithPath("petCategory").type(JsonFieldType.STRING).description("동반할 반려동물 종"),
					fieldWithPath("weight").type(JsonFieldType.STRING).description("동반할 반려동물 무게")
				)
			)).andDo(print());
	}

	@Test
	@DisplayName("Retrieve reservation - success")
	void retrieveReservation() throws Exception {
		//given
		ReservationRetrieveResponse reservationRetrieveResponse = new ReservationRetrieveResponse(reservationId, userId,
			roomId, accommodationId, accommodationName, roomName, checkInDate, checkOutDate, petCategory, weight);

		when(reservationService.findbyReservationId(anyLong())).thenReturn(reservationRetrieveResponse);
		//when
		ResultActions resultActions = mockMvc.perform(get("/reservation/{reservation-id}", reservationId)
			.accept(MediaType.APPLICATION_JSON));
		//then
		resultActions.andExpect(status().isOk())
			.andDo(print())
			.andDo(document("reservation-retrieval",
				pathParameters(
					parameterWithName("reservation-id").description("조회할 예약 id(pk)")
				),
				responseFields(
					fieldWithPath("reservationId").type(JsonFieldType.NUMBER).description("조회된 예약 아이디(pk)"),
					fieldWithPath("roomId").type(JsonFieldType.NUMBER).description("조회된 Room 아이디"),
					fieldWithPath("userId").type(JsonFieldType.NUMBER).description("숙박 시설을 예약한 유저 아이디"),
					fieldWithPath("accommodationId").type(JsonFieldType.NUMBER).description("예약한 숙박 시설 아이디"),
					fieldWithPath("accommodationName").type(JsonFieldType.STRING).description("예약한 숙박 시설 이름"),
					fieldWithPath("roomName").type(JsonFieldType.STRING).description("예약한 Room 이름"),
					fieldWithPath("checkInDate").type(JsonFieldType.STRING).description("체크인 날짜 및 시간"),
					fieldWithPath("checkOutDate").type(JsonFieldType.STRING).description("체크아웃 날짜 및 시간"),
					fieldWithPath("petCategory").type(JsonFieldType.STRING).description("동반할 반려동물 종"),
					fieldWithPath("weight").type(JsonFieldType.STRING).description("동반할 반려동물 무게")
				)
			));
	}

	@Test
	@DisplayName("Update reservation - success")
	void updateReservation() throws Exception {
		//given
		ReservationUpdatingRequest reservationUpdatingRequest = new ReservationUpdatingRequest(userId, roomId,
			checkInDate, checkOutDate, petCategory, weight);

		ReservationDetailsResponse reservationDetailsResponse = new ReservationDetailsResponse(reservationId, userId,
			roomId, checkInDate, checkOutDate, petCategory, weight);

		when(reservationService.updateReservation(anyLong(), any(ReservationUpdatingRequest.class))).thenReturn(
			reservationDetailsResponse);
		//when
		ResultActions resultActions = mockMvc.perform(
			put("/reservation/{reservation-id}", reservationId)
				.content(objectMapper.writeValueAsString(reservationUpdatingRequest))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON));
		//then
		resultActions.andExpect(status().isOk())
			.andDo(document("reservation-update",
				pathParameters(
					parameterWithName("reservation-id").description("수정할 예약 id")
				),
				requestFields(
					fieldWithPath("roomId").type(JsonFieldType.NUMBER).description("예약한 Room 아이디"),
					fieldWithPath("userId").type(JsonFieldType.NUMBER).description("숙박 시설을 예약한 유저 아이디"),
					fieldWithPath("checkInDate").type(JsonFieldType.STRING).description("변경 할 체크인 날짜 및 시간"),
					fieldWithPath("checkOutDate").type(JsonFieldType.STRING).description("변경 할 체크아웃 날짜 및 시간"),
					fieldWithPath("petCategory").type(JsonFieldType.STRING).description("변경 할 동반할 반려동물 종"),
					fieldWithPath("weight").type(JsonFieldType.STRING).description("변경 할 동반할 반려동물 무게")
				),
				responseFields(
					fieldWithPath("reservationId").type(JsonFieldType.NUMBER).description("변경된 예약 아이디(pk)"),
					fieldWithPath("roomId").type(JsonFieldType.NUMBER).description("예약한 Room 아이디"),
					fieldWithPath("userId").type(JsonFieldType.NUMBER).description("숙박 시설을 예약한 유저 아이디"),
					fieldWithPath("checkInDate").type(JsonFieldType.STRING).description("변경 된 체크인 날짜 및 시간"),
					fieldWithPath("checkOutDate").type(JsonFieldType.STRING).description("변경 된 체크아웃 날짜 및 시간"),
					fieldWithPath("petCategory").type(JsonFieldType.STRING).description("변경 된 동반할 반려동물 종"),
					fieldWithPath("weight").type(JsonFieldType.STRING).description("변경 된 동반할 반려동물 무게")
				)
			)).andDo(print());
	}

	@Test
	@DisplayName("Delete reservation - success")
	void deleteReservation() throws Exception {
		//given
		DeleteReservationRequest deleteReservationRequest = new DeleteReservationRequest(userId, reservationId);

		DeleteReservationResponse deleteReservationResponse = new DeleteReservationResponse(reservationId, true);

		when(reservationService.deleteReservation(any(DeleteReservationRequest.class))).thenReturn(
			deleteReservationResponse);
		//when
		ResultActions resultActions = mockMvc.perform(
			delete("/reservation/{reservation-id}", reservationId)
				.content(objectMapper.writeValueAsString(deleteReservationRequest))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON));
		//then
		resultActions.andExpect(status().isOk())
			.andDo(document("reservation-delete",
				pathParameters(
					parameterWithName("reservation-id").description("삭제할 예약 id")
				),
				requestFields(
					fieldWithPath("reservationId").type(JsonFieldType.NUMBER).description("삭제할 예약 아이디"),
					fieldWithPath("userId").type(JsonFieldType.NUMBER).description("삭제를 요청할 유저 아이디")
				),
				responseFields(
					fieldWithPath("reservationId").type(JsonFieldType.NUMBER).description("삭제한 예약 아이디(pk)"),
					fieldWithPath("state").type(JsonFieldType.BOOLEAN)
						.description("삭제 여부 true : 삭제 false : 삭제 안됨")
				))).andDo(print());
	}
}