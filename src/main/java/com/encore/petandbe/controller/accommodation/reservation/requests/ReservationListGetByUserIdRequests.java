package com.encore.petandbe.controller.accommodation.reservation.requests;

import lombok.Getter;

@Getter
public class ReservationListGetByUserIdRequests {

	private final Long userId;
	private final int pageNum;
	private final int amount;

	public ReservationListGetByUserIdRequests(Long userId, int pageNum, int amount) {
		this.userId = userId;
		this.pageNum = pageNum;
		this.amount = amount;
	}
}